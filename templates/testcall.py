from openai import OpenAI

#base_url = "https://api.aimlapi.com/v1"
base_url = "http://localhost:1234/v1/"
 
# Insert your AIML API key in the quotation marks instead of <YOUR_AIMLAPI_KEY>:
api_key = "not-needed"

system_prompt = "You are a travel agent. Be descriptive and helpful."
user_prompt = "Tell me about San Francisco"

api = OpenAI(base_url=base_url, api_key=api_key)

def main():
    completion = api.chat.completions.create(
        model="gemma-3-4b-it",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.7,
        max_tokens=256,
    )

    response = completion.choices[0].message.content

    print("User:", user_prompt)
    print("AI:", response)


if __name__ == "__main__":
    main()

