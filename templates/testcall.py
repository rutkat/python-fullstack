from openai import OpenAI

base_url = "http://localhost:1234/v1/"
 
system_prompt = "You are a learning assistant and teacher. Respond with accurate answers. If you don't know the answer, then be honest."
user_prompt = "Help me learn how to use AI. Provide a learning outline."

api = OpenAI(base_url=base_url, api_key="none")

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

