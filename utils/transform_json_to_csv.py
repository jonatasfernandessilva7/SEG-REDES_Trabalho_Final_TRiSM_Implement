import json
import pandas as pd
from pathlib import Path

def convert_log_to_csv(input_path: Path, output_csv: Path):
    encodings = ['utf-8-sig', 'utf-8', 'latin-1', 'cp1252']
    data = None
    for enc in encodings:
        try:
            with open(input_path, 'r', encoding=enc) as f:
                first_char = f.read(1)
                f.seek(0)
                if first_char == '[':
                    # JSON array
                    data = json.load(f)
                else:
                    # JSONL (um JSON por linha)
                    data = []
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data.append(json.loads(line))
                        except json.JSONDecodeError as e:
                            print(f"Linha {line_num} ignorada (erro JSON): {e}")
                            print(f"Conteúdo: {line[:100]}...")
            print(f"Arquivo lido com codificação {enc}")
            break
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            print(f"Falha com {enc}: {e}")
            continue
        except Exception as e:
            print(f"Erro inesperado com {enc}: {e}")
            continue

    if data is None:
        print("Não foi possível ler o arquivo com nenhuma codificação.")
        return

    if not data:
        print("Nenhum dado encontrado no arquivo.")
        return

    df = pd.DataFrame(data)
    df.to_csv(output_csv, index=False, encoding='utf-8-sig')
    print(f"Convertido {len(df)} registros para {output_csv}")

if __name__ == "__main__":
    input_file = Path(r"C:\Users\jonat\Downloads\SEG-REDES_Trabalho_Final_TRiSM_Implement\IA_com_TRiSM\tests\trism_execution_log_20260516_122822.json")
    output_file = Path(r"C:\Users\jonat\Downloads\SEG-REDES_Trabalho_Final_TRiSM_Implement\analise_dos_resultados\audit_data.csv")

    if input_file.exists():
        convert_log_to_csv(input_file, output_file)
    else:
        print(f"Arquivo não encontrado: {input_file}")
        root = input_file.parent.parent.parent 
        if not root.exists():
            root = Path.cwd()  
        print(f"Procurando em: {root}")
        for f in root.rglob("*.json") + list(root.rglob("*.jsonl")):
            print(f"Encontrado: {f}")