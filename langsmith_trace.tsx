# install npm module and get API key
# npm install langsmith
#
# export LANGSMITH_TRACING=true
# export LANGSMITH_API_KEY=<your-api-key>
# export LANGSMITH_PROJECT=default

import { OpenAI } from "openai";
import { wrapOpenAI } from "langsmith/wrappers";
# with traceable you can trace the entire chain
# import { traceable } from "langsmith/traceable";

const openAIClient = wrapOpenAI(new OpenAI());

async function retriever(query: string) {
  return ["This is a document"];
}

# replace async function with traceable()
# const rag = traceable(async function rag(question: string) {

async function rag(question: string) {
  const docs = await retriever(question);

  const systemMessage =
    "Answer the users question using only the provided information below:\n\n" +
    docs.join("\n");

  return await openAIClient.chat.completions.create({
    messages: [
      { role: "system", content: systemMessage },
      { role: "user", content: question },
    ],
    model: "gpt-4o-mini",
  });
}

rag("ask your question here")
