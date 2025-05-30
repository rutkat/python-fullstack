
from langchain_ollama.llms import OllamaLLM
from langchain_community.document_loaders import WebBaseLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.embeddings import GPT4AllEmbeddings
from langchain_community.vectorstores import Chroma

# Import chains
from langchain.chains import RetrievalQA

ollama = OllamaLLM(base_url='http://localhost:11434', model='llama3.2')

# Load the document from a URL
loader = WebBaseLoader('https://lilianweng.github.io/posts/2023-06-23-agent/')
# Load the document contents as 'data'
data = loader.load()
# Define the 'text_splitter' params
text_splitter = RecursiveCharacterTextSplitter(chunk_size=200, chunk_overlap=3)
# Split the 'data'
all_splits = text_splitter.split_documents(data)
# Instantiate the vector store
vectorstore = Chroma.from_documents(documents=all_splits, embedding=GPT4AllEmbeddings())
# Use chains to link tasks
qachain = RetrievalQA.from_chain_type(ollama, retriever=vectorstore.as_retriever())

question = "What are the components of autonomus agents?"
print(qachain({"query": question}))





