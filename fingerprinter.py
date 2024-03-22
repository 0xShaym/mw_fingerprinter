import hashlib
import ssdeep
import pefile  # Assurez-vous d'installer pefile avec pip install pefile
import argparse
import os

def is_pefile(file_path):
    try:
        pe = pefile.PE(file_path)
        return True
    except pefile.PEFormatError:
        return False

def calculate_hashes(file_path):
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    ssdeep_hash = ""
    imphash = ""

    with open(file_path, "rb") as file:
        # Calculer les hachages MD5, SHA-1 et SHA-256
        while chunk := file.read(8192):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)

        # Calculer le hash SSDEEP
        file.seek(0)
        ssdeep_hash = ssdeep.hash(file.read())

        # Calculer le hash IMPHASH pour les fichiers PE
        if is_pefile(file_path):
            pe = pefile.PE(file_path)
            imphash = pe.get_imphash()
        else:
            imphash = "Not a PE file"

    return md5_hash.hexdigest(), sha1_hash.hexdigest(), sha256_hash.hexdigest(), ssdeep_hash, imphash

def generate_md_content(file_path, md5, sha1, sha256, ssdeep_hash, imphash):
    content = f"# File hashes for : {file_path}\n"
    content += f"MD5: {md5}\n"
    content += f"SHA-1: {sha1}\n"
    content += f"SHA-256: {sha256}\n"
    content += f"SSDEEP: {ssdeep_hash}\n"
    content += f"IMPHASH: {imphash}\n\n"
    return content

def analyze_sample(sample_path, output_folder):
    if not os.path.exists(sample_path):
        print(f"Le chemin spécifié {sample_path} n'existe pas.")
        return

    if os.path.isfile(sample_path):
        md5, sha1, sha256, ssdeep_hash, imphash = calculate_hashes(sample_path)
        md_content = generate_md_content(sample_path, md5, sha1, sha256, ssdeep_hash, imphash)
        sample_name = os.path.splitext(os.path.basename(sample_path))[0] + ".md"
        output_path = os.path.join(output_folder, sample_name)
        with open(output_path, "w") as md_file:
            md_file.write(md_content)
        print(f"Le fichier MD a été créé pour : {sample_path} -> {output_path}")
    elif os.path.isdir(sample_path):
        for root, _, files in os.walk(sample_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                analyze_sample(file_path, output_folder)

def main():
    parser = argparse.ArgumentParser(description="Script de calcul des hachages MD5, SHA-1, SHA-256, SSDEEP et IMPHASH d'un fichier ou d'un dossier.")
    parser.add_argument("sample", help="Chemin vers un fichier ou un dossier contenant des échantillons à analyser.")
    args = parser.parse_args()

    # Créer le dossier sample_analysed au même niveau que le premier échantillon analysé
    first_sample_parent_folder = os.path.dirname(args.sample)
    output_folder = os.path.join(first_sample_parent_folder, "sample_analysed")
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    analyze_sample(args.sample, output_folder)

if __name__ == "__main__":
    main()
