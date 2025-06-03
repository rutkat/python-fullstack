# install pkg and get API key
# pip install langsmith
#
# export LANGSMITH_TRACING=true
# export LANGSMITH_API_KEY=<your-api-key>
# export LANGSMITH_PROJECT=default

from openai import OpenAI
from langsmith.wrappers import wrap_openai
# Trace the whole chain with traceable
# from langsmith import traceable


openai_client = wrap_openai(OpenAI())

def retriever(query: str):
    results = ["Returned results go here in the retriever function"]
    return results

# use a decorator above the rag() function
# @traceable
def rag(question):
    docs = retriever(question)
    system_message = """Answer the users question using only the provided information below:
    
    {docs}""".format(docs="\n".join(docs))
    
    return openai_client.chat.completions.create(
        messages=[
            {"role": "system", "content": system_message},
            {"role": "user", "content": question},
        ],
        model="gpt-4o-mini",
    )

# This will produce a trace and display it in the UI
rag("where do the results go?")





