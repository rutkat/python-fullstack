from openai import OpenAI

# Configure OpenAI client to use the local server
API_BASE = "http://127.0.0.1:1234/v1"
API_KEY = "not-needed"  # Placeholder, required even if not used
MODEL = "hermes-3-llama-3.2-3b"

openai = OpenAI(base_url=API_BASE, api_key=API_KEY)

# Initialize chat history with system prompt
messages = [
    {"role": "system", "content": "You are a helpful assistant."}
]

print("Chat with your local LLM. Type 'exit' to quit.")

while True:
    user_input = input("You: ")
    if user_input.strip() in {"exit", "quit"}:
        break

    messages.append({"role": "user", "content": user_input})

    try:
        response = openai.chat.completions.create(
            model=MODEL,
            messages=messages,
	    temperature=0.2
        )

        reply = response.choices[0].message.content
        print(reply)
        messages.append({"role": "assistant", "content": reply})
    except Exception as e:
        print(f"Error: {e}"

)
