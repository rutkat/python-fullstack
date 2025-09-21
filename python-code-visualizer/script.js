
class PythonVisualizer {
    constructor() {
        this.code = '';
        this.lines = [];
        this.currentLine = 0;
        this.executionState = [];
        this.isRunning = false;
        this.isPaused = false;
        this.delay = 1000;
        
        this.initializeElements();
        this.attachEventListeners();
        this.updateLineNumbers();
    }

    initializeElements() {
        this.codeInput = document.getElementById('codeInput');
        this.visualizer = document.getElementById('visualizer');
        this.runBtn = document.getElementById('runBtn');
        this.stepBtn = document.getElementById('stepBtn');
        this.resetBtn = document.getElementById('resetBtn');
        this.statusText = document.getElementById('statusText');
        this.lineInfo = document.getElementById('lineInfo');
        this.lineNumbers = document.getElementById('lineNumbers');
        this.speedSlider = document.getElementById('speedSlider');
        this.speedValue = document.getElementById('speedValue');
        this.examplesBtn = document.getElementById('examplesBtn');
        this.examplesMenu = document.getElementById('examplesMenu');
    }

    attachEventListeners() {
        this.runBtn.addEventListener('click', () => this.run());
        this.stepBtn.addEventListener('click', () => this.step());
        this.resetBtn.addEventListener('click', () => this.reset());
        this.codeInput.addEventListener('input', () => this.updateLineNumbers());
        this.codeInput.addEventListener('scroll', () => this.syncScroll());
        this.speedSlider.addEventListener('input', (e) => {
            this.delay = parseInt(e.target.value);
            this.speedValue.textContent = (this.delay / 1000).toFixed(1) + 's';
        });
        
        this.examplesBtn.addEventListener('click', () => {
            this.examplesMenu.classList.toggle('show');
        });
        
        document.querySelectorAll('.example-item').forEach(item => {
            item.addEventListener('click', (e) => {
                this.loadExample(e.target.dataset.example);
                this.examplesMenu.classList.remove('show');
            });
        });
        
        document.addEventListener('click', (e) => {
            if (!this.examplesBtn.contains(e.target) && !this.examplesMenu.contains(e.target)) {
                this.examplesMenu.classList.remove('show');
            }
        });
    }

    updateLineNumbers() {
        const lines = this.codeInput.value.split('\n');
        this.lineNumbers.innerHTML = lines.map((_, i) => `<div>${i + 1}</div>`).join('');
    }

    syncScroll() {
        // Synchronize scrolling between line numbers and code input
        this.lineNumbers.scrollTop = this.codeInput.scrollTop;
    }

    loadExample(example) {
        const examples = {
            fibonacci: `# Fibonacci sequence example
def fibonacci(n):
a, b = 0, 1
result = []

for i in range(n):
result.append(a)
a, b = b, a + b

return result

# Calculate first 8 Fibonacci numbers
fib_numbers = fibonacci(8)
print(fib_numbers)`,
            
            bubble: `# Bubble Sort Algorithm
def bubble_sort(arr):
n = len(arr)

for i in range(n):
swapped = False

for j in range(n - i - 1):
    if arr[j] > arr[j + 1]:
        arr[j], arr[j + 1] = arr[j + 1], arr[j]
        swapped = True

if not swapped:
    break

return arr

# Sort a list
numbers = [64, 34, 25, 12, 22, 11, 90]
sorted_nums = bubble_sort(numbers.copy())
print(sorted_nums)`,
            
            factorial: `# Factorial calculation
def factorial(n):
if n <= 1:
return 1

result = 1
for i in range(2, n + 1):
result *= i

return result

# Calculate factorials
for num in range(1, 8):
fact = factorial(num)
print(f"{num}! = {fact}")`,
            
            prime: `# Find prime numbers
def is_prime(n):
if n < 2:
return False

for i in range(2, int(n ** 0.5) + 1):
if n % i == 0:
    return False

return True

# Find primes up to 30
primes = []
for num in range(2, 31):
if is_prime(num):
primes.append(num)

print("Primes:", primes)`,
            
            nested: `# Nested loops example
def multiplication_table(size):
table = []

for i in range(1, size + 1):
row = []
for j in range(1, size + 1):
    product = i * j
    row.append(product)
table.append(row)

return table

# Generate 5x5 table
table = multiplication_table(5)
for row in table:
print(row)`
        };
        
        this.codeInput.value = examples[example] || examples.fibonacci;
        this.updateLineNumbers();
        this.reset();
    }

    parseCode() {
        this.code = this.codeInput.value;
        this.lines = this.code.split('\n');
        this.executionState = this.simulateExecution();
    }

    simulateExecution() {
        const states = [];
        const lines = this.lines;
        let globalScope = { name: 'Global', type: 'global', variables: {} };
        let currentScope = globalScope;
        let scopes = [globalScope];
        
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            
            if (line === '' || line.startsWith('#')) continue;
            
            const state = {
                line: i,
                scopes: JSON.parse(JSON.stringify(scopes)),
                message: ''
            };
            
            // Function definition
            if (line.startsWith('def ')) {
                const funcName = line.match(/def\s+(\w+)/)[1];
                const funcScope = { name: funcName, type: 'function', variables: {}, parent: 0 };
                scopes.push(funcScope);
                currentScope = funcScope;
                state.message = `Defining function: ${funcName}`;
            }
            // Variable assignment
            else if (line.includes('=') && !line.includes('==')) {
                const parts = line.split('=');
                if (parts.length >= 2) {
                    const varNames = parts[0].trim().split(',').map(v => v.trim());
                    const values = this.evaluateExpression(parts[1].trim());
                    
                    varNames.forEach((varName, idx) => {
                        if (varName && !varName.includes('[')) {
                            currentScope.variables[varName] = values[idx] || values;
                            state.message = `${varName} = ${values[idx] || values}`;
                        }
                    });
                }
            }
            // For loop
            else if (line.startsWith('for ')) {
                const match = line.match(/for\s+(\w+)\s+in\s+range\((\d+)/);
                if (match) {
                    const loopVar = match[1];
                    const limit = parseInt(match[2]);
                    
                    for (let j = 0; j < Math.min(limit, 5); j++) {
                        const loopScope = { 
                            name: `Loop iteration ${j}`, 
                            type: 'loop',
                            variables: { [loopVar]: j },
                            parent: scopes.length - 1
                        };
                        
                        const loopState = {
                            line: i,
                            scopes: [...scopes, loopScope],
                            message: `Loop: ${loopVar} = ${j}`
                        };
                        states.push(loopState);
                    }
                }
            }
            // If statement
            else if (line.startsWith('if ')) {
                const condition = line.substring(3, line.length - 1);
                state.message = `Checking condition: ${condition}`;
            }
            // Return statement
            else if (line.startsWith('return')) {
                if (scopes.length > 1) {
                    scopes.pop();
                    currentScope = scopes[scopes.length - 1];
                }
                state.message = 'Returning from function';
            }
            
            states.push(state);
        }
        
        return states;
    }

    evaluateExpression(expr) {
        expr = expr.trim();
        
        // String
        if (expr.startsWith('"') || expr.startsWith("'")) {
            return expr.slice(1, -1);
        }
        // List
        if (expr.startsWith('[')) {
            return '[]';
        }
        // Number
        if (!isNaN(expr)) {
            return parseInt(expr);
        }
        // Boolean
        if (expr === 'True' || expr === 'False') {
            return expr;
        }
        // Multiple values
        if (expr.includes(',')) {
            return expr.split(',').map(v => this.evaluateExpression(v.trim()));
        }
        // Function call
        if (expr.includes('(')) {
            return 'function_result';
        }
        
        return expr;
    }

    visualizeState(state) {
        this.visualizer.innerHTML = '';
        
        state.scopes.forEach((scope, idx) => {
            const scopeDiv = document.createElement('div');
            scopeDiv.className = scope.parent !== undefined ? 'scope nested-scope' : 'scope';
            
            const header = document.createElement('div');
            header.className = 'scope-header';
            header.innerHTML = `
                <span>${scope.name}</span>
                <span class="scope-type">${scope.type}</span>
            `;
            scopeDiv.appendChild(header);
            Object.entries(scope.variables).forEach(([name, value]) => {
                const varDiv = document.createElement('div');
                varDiv.className = 'variable';


                let valueClass = 'var-value';
                if (typeof value === 'string') valueClass += ' string';
                else if (typeof value === 'number') valueClass += ' number';
                else if (typeof value === 'boolean') valueClass += ' boolean';
                
                varDiv.innerHTML = `
                    <span class="var-name">${name} (${typeof value})</span>
                    <span class="${valueClass}">${JSON.stringify(value)}</span>
                `;
                scopeDiv.appendChild(varDiv);
            });
            
            if (Object.keys(scope.variables).length === 0) {
                scopeDiv.innerHTML += '<div style="color: #999; font-size: 14px;">No variables yet</div>';
            }
            
            this.visualizer.appendChild(scopeDiv);
        });
        
        if (state.message) {
            const messageDiv = document.createElement('div');
            messageDiv.style.cssText = 'background: #e3f2fd; padding: 10px; border-radius: 6px; margin-top: 10px; color: #1976d2;';
            messageDiv.textContent = `💡 ${state.message}`;
            this.visualizer.appendChild(messageDiv);
        }
        
        this.highlightLine(state.line);
        this.lineInfo.textContent = `Line: ${state.line + 1}`;
    }

    highlightLine(lineNumber) {
        const lines = this.codeInput.value.split('\n');
        const lineElements = this.lineNumbers.children;
        
        Array.from(lineElements).forEach((el, idx) => {
            if (idx === lineNumber) {
                el.style.background = 'rgba(255, 235, 59, 0.3)';
                el.style.fontWeight = 'bold';
            } else {
                el.style.background = 'transparent';
                el.style.fontWeight = 'normal';
            }
        });
    }

    async run() {
        if (this.isRunning) {
            this.isPaused = !this.isPaused;
            this.runBtn.textContent = this.isPaused ? '▶️ Resume' : '⏸️ Pause';
            return;
        }
        
        this.parseCode();
        this.isRunning = true;
        this.isPaused = false;
        this.currentLine = 0;
        this.runBtn.textContent = '⏸️ Pause';
        this.stepBtn.disabled = true;
        this.statusText.textContent = 'Running...';
        
        for (let i = 0; i < this.executionState.length; i++) {
            if (!this.isRunning) break;
            
            while (this.isPaused) {
                await new Promise(resolve => setTimeout(resolve, 100));
            }
            
            this.visualizeState(this.executionState[i]);
            await new Promise(resolve => setTimeout(resolve, this.delay));
        }
        
        this.isRunning = false;
        this.runBtn.textContent = '▶️ Run';
        this.stepBtn.disabled = false;
        this.statusText.textContent = 'Completed';
    }

    step() {
        if (!this.executionState.length) {
            this.parseCode();
        }
        
        if (this.currentLine < this.executionState.length) {
            this.visualizeState(this.executionState[this.currentLine]);
            this.currentLine++;
            this.statusText.textContent = `Step ${this.currentLine}/${this.executionState.length}`;
        } else {
            this.statusText.textContent = 'Completed';
        }
    }

    reset() {
        this.isRunning = false;
        this.isPaused = false;
        this.currentLine = 0;
        this.executionState = [];
        this.runBtn.textContent = '▶️ Run';
        this.stepBtn.disabled = false;
        this.statusText.textContent = 'Ready';
        this.lineInfo.textContent = 'Line: -';
        this.visualizer.innerHTML = '<div style="text-align: center; color: #999; padding: 50px;">Click "Run" or "Step" to visualize code execution</div>';
        
        Array.from(this.lineNumbers.children).forEach(el => {
            el.style.background = 'transparent';
            el.style.fontWeight = 'normal';
        });
    }
}

// Initialize the visualizer
const visualizer = new PythonVisualizer();
