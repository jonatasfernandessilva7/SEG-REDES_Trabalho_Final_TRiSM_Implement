import ollama

class OllamaChat:
    def __init__(self, model: str = "phi3.5"):
        self.model = model
        self.conversation_history = []
    
    def send_message(self, user_message: str) -> str:
        """Send a message and get response from ollama"""
        # Add user message to history
        self.conversation_history.append({
            "role": "user",
            "content": user_message
        })
        
        # Get response from ollama
        response = ollama.chat(
            model=self.model,
            messages=self.conversation_history
        )
        
        assistant_message = response['message']['content']
        
        # Add assistant response to history
        self.conversation_history.append({
            "role": "assistant",
            "content": assistant_message
        })
        
        return assistant_message
    
    def send_message_stream(self, user_message: str):
        """Send a message and stream response from ollama"""
        # Add user message to history
        self.conversation_history.append({
            "role": "user",
            "content": user_message
        })
        
        # Get response from ollama with streaming
        stream = ollama.chat(
            model=self.model,
            messages=self.conversation_history,
            stream=True
        )
        
        assistant_message = ""
        for chunk in stream:
            content = chunk['message']['content']
            print(content, end='', flush=True)
            assistant_message += content
        
        print()  # New line after streaming
        
        # Add assistant response to history
        self.conversation_history.append({
            "role": "assistant",
            "content": assistant_message
        })
        
        return assistant_message
    
    def clear_history(self):
        """Clear conversation history"""
        self.conversation_history = []
    
    def get_history(self):
        """Get conversation history"""
        return self.conversation_history


def main():
    """Main chat loop"""
    chat = OllamaChat()
    print("Ollama Chat (type 'exit' to quit, 'clear' to clear history)")
    print("=" * 50)
    
    while True:
        try:
            user_input = input("\nYou: ").strip()
            
            if user_input.lower() == 'exit':
                print("Goodbye!")
                break
            
            if user_input.lower() == 'clear':
                chat.clear_history()
                print("Chat history cleared.")
                continue
            
            if not user_input:
                continue
            
            print("\nAssistant: ", end='')
            chat.send_message_stream(user_input)
        
        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            break


if __name__ == "__main__":
    main()
