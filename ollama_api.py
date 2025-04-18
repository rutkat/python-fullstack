# requirements.txt
# ollama
#
# Install ollama from the website or cli `brew install ollama`
# Start the server with `ollama serve`
# Run the model available through ollama `ollama run <model>`
#
 
from ollama import chat
#from ollama import Client

# The model you have downloaded locally using the command "ollama pull <model>"
MODEL = "llama3.2"

prompt = "List all of the presidents of the United States in chronological order."
role = 'user'

# if you need to specify a different server, default is localhost
#client = Client(
#  host='http://localhost:11434'
#)

response = chat(
  model=MODEL, 
  messages=[{
    'role': role,
    'content': prompt
  }],
  stream=True,
)

for chunk in response:
  print(chunk['message']['content'], end='', flush=True)



