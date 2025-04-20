# Python template to demonstrate newer API call to OpenAI models using the chat.respones.create()
# Gives the ability to perform multi-turn model interactions in a single API call
# POST https://api.openai.com/v1/responses
# Announced March 2025
from openai import OpenAI

base_url = "http://localhost:1234/v1"
 
system_prompt = "You are a learning assistant and teacher. Respond with accurate answers. If you don't know the answer, then be honest."
user_prompt = "Help me learn how to use AI. Provide a learning outline."

client = OpenAI(base_url=base_url, api_key="none")

stream = client.responses.create(
    model = "gemma-3-4b-it",
    input = [
        {
            "role": "user",
            "content": "Say 'double bubble bath' ten times fast.",
        },
    ],
    stream=True,
)

for event in stream:
    print(event)