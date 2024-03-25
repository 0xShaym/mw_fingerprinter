import hashlib
import ssdeep
import pefile
import argparse
import os
import subprocess

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
        while chunk := file.read(8192):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)

        file.seek(0)
        ssdeep_hash = ssdeep.hash(file.read())

        if is_pefile(file_path):
            pe = pefile.PE(file_path)
            imphash = pe.get_imphash()
        else:
            imphash = "Not a PE file"

    return md5_hash.hexdigest(), sha1_hash.hexdigest(), sha256_hash.hexdigest(), ssdeep_hash, imphash

def generate_md_content(file_path, md5, sha1, sha256, ssdeep_hash, imphash, clamav_result=None, trid_result=None, file_info=None, strings_output=None, hexdump_head=None, hexdump_tail=None):
    content = f"# File hashes for : {file_path}\n"
    content += f"MD5 : {md5}\n"
    content += f"SHA-1 : {sha1}\n"
    content += f"SHA-256 : {sha256}\n"
    content += f"SSDEEP : {ssdeep_hash}\n"
    content += f"IMPHASH : {imphash}\n"
    content += f"# File Info : \n{file_info}\n"
    content += f"# ClamAV Result : \n{clamav_result}\n"
    content += f"# TRID Result : \n{trid_result}\n"
    content += f"# Hexdump Head : \n{hexdump_head}\n"
    content += f"# Hexdump Tail : \n{hexdump_tail}\n"
    content += f"# Strings Output : \n{strings_output}\n\n"
    
    return content

def analyze_sample(sample_path, output_folder, run_clamav=False):
    if not os.path.exists(sample_path):
        print(f"Path {sample_path} does not exist.")
        return

    if os.path.isfile(sample_path):
        md5, sha1, sha256, ssdeep_hash, imphash = calculate_hashes(sample_path)
        
        clamav_result = ""
        if run_clamav:
            try:
                clamav_result = subprocess.run(["clamscan", "--no-summary", sample_path], capture_output=True, text=True).stdout.strip()
            except Exception as e:
                print("Try clamscan but an error occurs : ", e)
        try:
            trid_result = subprocess.run(["trid", sample_path], capture_output=True, text=True).stdout.strip()
        except Exception as e:
            print("Try trid but an error occurs : ", e)
        try:
            file_info = subprocess.run(["file", sample_path], capture_output=True, text=True).stdout.strip()
        except Exception as e:
            print("Try file but an error occurs : ", e)
        try:
            strings_output = subprocess.run(["strings", "-n", "5", sample_path], capture_output=True, text=True).stdout.strip()
        except Exception as e:
            print("Try strings but an error occurs : ", e)
        try:
            hexdump_head = subprocess.run(["hexdump", "-C", sample_path], capture_output=True, text=True).stdout.strip()
            hexdump_tail = subprocess.run(["hexdump", "-C", sample_path], capture_output=True, text=True).stdout.strip()
        except Exception as e:
            print("Try hexdump but an error occurs : ", e)
        md_content = generate_md_content(sample_path, md5, sha1, sha256, ssdeep_hash, imphash, clamav_result, trid_result, file_info, strings_output, hexdump_head, hexdump_tail)
        sample_name = os.path.splitext(os.path.basename(sample_path))[0] + ".md"
        output_path = os.path.join(output_folder, sample_name)
        with open(output_path, "w") as md_file:
            md_file.write(md_content)
        print(f"The MD file was created for : {sample_path} -> {output_path}")
    elif os.path.isdir(sample_path):
        for root, _, files in os.walk(sample_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                output_file_path = os.path.join(output_folder, os.path.splitext(file_name)[0] + ".md")
                if not os.path.exists(output_file_path):
                    analyze_sample(file_path, output_folder, run_clamav)

def main():
    parser = argparse.ArgumentParser(description="Script for calculating the MD5, SHA-1, SHA-256, SSDEEP and IMPHASH hashes of a file or folder.")
    parser.add_argument("sample", help="Path to a file or folder containing samples to analyze.")
    parser.add_argument("--clamav", action="store_true", help="Do the freshclam and the ClamAV scan.")
    args = parser.parse_args()

    first_sample_parent_folder = os.path.dirname(args.sample)
    output_folder = os.path.join(first_sample_parent_folder, "sample_analysed")
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    
    if args.clamav:
        try:
            subprocess.run(["sudo", "freshclam"])
        except Exception as e:
            print("Try freshclam but an error occurs : ", e)
    analyze_sample(args.sample, output_folder, args.clamav)

if __name__ == "__main__":
    main()
