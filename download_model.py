import os
from huggingface_hub import hf_hub_download

def download_model():
    repo_id = "bartowski/Llama-3.2-1B-Instruct-GGUF"
    filename = "Llama-3.2-1B-Instruct-Q4_K_M.gguf"
    
    print(f"Downloading {filename} from {repo_id}...")
    
    os.makedirs("models", exist_ok=True)
    
    # Download the model to the local huggingface cache and get the path
    model_path = hf_hub_download(
        repo_id=repo_id,
        filename=filename,
        local_dir="models",
        local_dir_use_symlinks=False
    )
    
    print(f"Model downloaded successfully to: {model_path}")

if __name__ == "__main__":
    download_model()
