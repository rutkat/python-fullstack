import os
from dotenv import load_dotenv
import requests
import json
from typing import List
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from IPython.display import Markdown, display, update_display
from openai import OpenAI


load_dotenv(override=True)
api_key = os.getenv('CLAUDE_API_KEY')

if api_key and len(api_key)>10:
    print("API key is present")
else:
    print("There is no API key in the env file!")
    
# Choose a model you downloaded from LM studio or using an api-key
# MODEL = 'claude-3-7-sonnet-20250219'
# MODEL = 'gemma-3-4b-it'
MODEL = 'hermes-3-llama-3.2-3b@q8_0'
# openai = OpenAI(base_url="https://api.anthropic.com/v1/", api_key=api_key)
openai = OpenAI(base_url="http://localhost:1234/v1/", api_key="no-key")

headers = {
 "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.10 Safari/605.1.1"
}

class Website:
  def __init__(self, url):
    self.url = url
    response = requests.get(url, headers=headers)
    self.body = response.content
    soup = BeautifulSoup(self.body, 'html.parser')
    if soup.title: 
      self.title = soup.title.string 
    else:
      self.title = "No title found"
    
    if soup.body:
      for irrelevant in soup.body(["script", "style", "img", "input"]):
        irrelevant.decompose()
        self.text = soup.body.get_text(separator="\n", strip=True)
      else:
        self.text = ""
        links = [link.get('href') for link in soup.find_all('a')]
        self.links = [link for link in links if link]

  def get_contents(self):
    return f"Webpage Title:\n{self.title}\nWebpage Contents:\n{self.text}\n\n"

link_sys_prompt = "You are provided with a list of links found on a webpage. \
You are able to decide which of the links would be most relevant to include in a brochure about the company, \
such as links to an About page, or a Company page, or Careers/Jobs pages.\n"
link_sys_prompt += "The reponse should be in JSON like this example:"
link_sys_prompt += """
{
    "links": [
        {"type": "about page", "url": "https://full.url/goes/here/about"},
        {"type": "careers page": "url": "https://another.full.url/careers"}
    ]
}
"""

def get_links_user_prompt(website):
  user_prompt = f"Here is the list of links on the website of {website.url} - "
  user_prompt += "please decide which of these are relevant web links for a brochure about the company, respond with the full https URL in JSON format. \
Do not include Terms of Service, Privacy, email links.\n"
  user_prompt += "Links (some might be relative links):\n"
  user_prompt += "\n".join(website.links)
  return user_prompt

def get_links(url):
  website = Website(url)
  response = openai.chat.completions.create(
     model=MODEL,
     messages=[
       {"role": "system", "content": link_sys_prompt},
       {"role": "user", "content": get_links_user_prompt(website)}
    ])
  result = response.choices[0].message.content
  return result

# print(get_links("https://huggingface.co"))

def get_details(url):
  result = "Landing page:\n" 
  result += Website(url).get_contents()
  links = get_links(url) 
  # recent api changes added markdown wrapping ticks ``` so remove them
  # links = links.replace('```', '').replace('json', '')
  print(links)
  for link in links["links"]:
    if link:
      result += f"\n\n{link['type']}\n"
      result += Website(link["url"]).get_contents()
  return result

system_prompt = "As a convincing salesperson, analyze the company's website pages and write a summary for prospective customers. Include the details you have available about the company and respond in mardown format."

def get_summary_prompt(company_name, url):
  user_prompt = f"The company website is: {company_name}\n"
  user_prompt += f"The contents of its website and other relevant pages; use this information for analysis.\n"
  user_prompt += get_details(url)
  return user_prompt

get_details('https://huggingface.co')
get_summary_prompt("Google Colab", "https://colab.google")


