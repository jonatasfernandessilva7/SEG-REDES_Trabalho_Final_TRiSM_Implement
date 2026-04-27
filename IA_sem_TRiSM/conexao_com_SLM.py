import ollama

'''
OBSERVAÇÃO STREAM
se for usado:
print(chunk['message']['content'], end='', flush=True)
no lugarde de
response += chunk['message']['content']
a saida vai ser gerada em tempo real no console, parecido com o gpt
'''

def conexao_phi_ollama_stream(prompt: str):
    stream = ollama.chat(
        model="phi3.5",
        messages=[
            {
                "role": "user", 
                "content": prompt
            }
        ],
        stream = True,
    )
    response = ""
    for chunk in stream:
        response += chunk['message']['content']
    return response

def conexao_phi_ollama(prompt: str):
    response = ollama.chat(
        model="phi3.5",
        messages=[
            {
                "role": "user", 
                "content": prompt
            }
        ]
    )
    return response['message']['content']  