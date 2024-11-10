from flask import Flask, render_template, request, jsonify, Response
import threading
import subprocess
import tempfile
import os
import signal
import platform
import time
import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold
from werkzeug.utils import secure_filename

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/info')
def info():
    return render_template('main.html')

@app.route('/solution')
def solution():
    return render_template('solution.html')


class CodeExecutionThread(threading.Thread):
    def __init__(self, code, timeout):
        super().__init__()
        self.code = code
        self.timeout = timeout
        self.process = None
        self.output = None
        self.error = None
        self.execution_time = None
        self.terminated = False

    def run(self):
        temp_file_path = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_file:
                temp_file.write(self.code)
                temp_file_path = temp_file.name

            start_time = time.time()
            
            self.process = subprocess.Popen(
                ['python', temp_file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            try:
                self.output, self.error = self.process.communicate(timeout=self.timeout)
                self.execution_time = time.time() - start_time
            except subprocess.TimeoutExpired:
                self.terminated = True
                self.terminate()
                self.output, self.error = self.process.communicate()
                
        except Exception as e:
            self.error = str(e).encode()
        finally:
            if temp_file_path and os.path.exists(temp_file_path):
                os.unlink(temp_file_path)

    def terminate(self):
        if self.process:
            if platform.system() == 'Windows':
                subprocess.run(['taskkill', '/F', '/T', '/PID', str(self.process.pid)], 
                             timeout=1, check=False)
            else:
                os.kill(self.process.pid, signal.SIGKILL)

@app.route('/analyze_thread', methods=['POST'])
def analyze_thread():
    code = request.form.get('code', '')
    timeout = min(int(request.form.get('timeout', 5)), 30)
    suspicious_patterns = ['while True', 'fork', 'Thread(', 'Process(']
    detected_patterns = [p for p in suspicious_patterns if p in code]
    
    if detected_patterns:
        return jsonify({
            'is_fork_bomb': True,
            'message': f"Suspicious patterns detected: {', '.join(detected_patterns)}"
        })

    execution_thread = CodeExecutionThread(code, timeout)
    execution_thread.start()
    execution_thread.join(timeout + 1)

    is_fork_bomb = execution_thread.terminated or execution_thread.error is not None
    
    if is_fork_bomb:
        message = "Fork bomb detected! "
        if execution_thread.terminated:
            message += f"Code exceeded {timeout} second timeout."
        if execution_thread.error:
            message += f"\nError: {execution_thread.error.decode('utf-8', errors='ignore')}"
    else:
        message = "Code appears safe. "
        if execution_thread.output:
            message += f"\nOutput: {execution_thread.output.decode('utf-8', errors='ignore')}"

    return jsonify({
        'is_fork_bomb': is_fork_bomb,
        'message': message
    })




genai.configure(api_key=os.getenv(GEMINI_API_KEY))
model = genai.GenerativeModel('gemini-1.5-flash')

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {
    'py', 'c', 'cpp', 'cs', 'java', 'js', 'go', 'rs', 
    'rb', 'php', 'pl', 'sh', 'bat', 'ps1', 'hs', 'erl',
    'nim', 'r', 'lua', 'lisp', 'scm', 'ada', 'asm', 'awk'
}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/analyze_ai', methods=['POST'])
def analyze_ai():
    print("hello")
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        language = request.form.get('language', '').lower()
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type'}), 400

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        with open(filepath, 'r') as f:
            code_content = f.read()

        prompt = f"""
        Analyze this {language} code and determine if it's a fork bomb, also tell us if its similar to any other known malicious code or if its an infinite loop.
        Code to analyze:
        {code_content}
        Provide a clear yes/no answer if this code is a fork bomb, followed by a brief explanation.
        """

        response = model.generate_content(prompt,
            safety_settings={
                HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_LOW_AND_ABOVE,
                HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE
            }
        )
        print(response.text.strip())
        return jsonify({
            'status': 'success',
            'analysis': response.text.strip()
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

    finally:
        if 'filepath' in locals() and os.path.exists(filepath):
            os.unlink(filepath)


if __name__ == '__main__':
    app.run(port=5002)
