#!/bin/bash

# Modify this path to where you want to store your results
recon_root="$HOME/recon_results"

# Modify this to where you cloned CloudHunter
cloudhunter_dir="$HOME/CloudHunter"

echo "[*] Installing required tools if missing..."
sudo apt update
sudo apt install -y subfinder sublist3r amass gobuster nmap python3-pip jq parallel git
pip3 install --quiet dirsearch nuclei httprobe

read -p "Enter path to domain list file: " domain_file
read -p "Enter comma-separated subdomain brute force wordlists: " subdomain_wordlists_str
read -p "Enter comma-separated directory brute force wordlists: " dir_wordlists_str
read -p "Enter max subdomain enumeration depth (e.g. 3): " max_depth

IFS=',' read -r -a subdomain_wordlists <<< "$subdomain_wordlists_str"
IFS=',' read -r -a dir_wordlists <<< "$dir_wordlists_str"

mkdir -p "$recon_root"

run_domain_recon() {
  domain=$1
  echo "[*] Starting recon on $domain"

  domain_dir="$recon_root/$domain"
  mkdir -p "$domain_dir"/{subfinder,sublist3r,amass,gobuster,nmap,cloudhunter,dirsearch,nuclei,httprobe,reports}

  # Passive subdomain enumeration
  subfinder -d "$domain" -o "$domain_dir/subfinder/subfinder.txt" || true
  sublist3r -d "$domain" -o "$domain_dir/sublist3r/sublist3r.txt" || true
  amass enum -passive -d "$domain" -o "$domain_dir/amass/amass_passive.txt" || true

  # Combine initial results if files exist
  files_to_combine=()
  [[ -f "$domain_dir/subfinder/subfinder.txt" ]] && files_to_combine+=("$domain_dir/subfinder/subfinder.txt")
  [[ -f "$domain_dir/sublist3r/sublist3r.txt" ]] && files_to_combine+=("$domain_dir/sublist3r/sublist3r.txt")
  [[ -f "$domain_dir/amass/amass_passive.txt" ]] && files_to_combine+=("$domain_dir/amass/amass_passive.txt")

  if (( ${#files_to_combine[@]} > 0 )); then
    sort -u "${files_to_combine[@]}" > "$domain_dir/all_subdomains_level_1.txt"
  else
    echo "[!] No initial subdomain files found for $domain. Skipping..."
    return
  fi

  current_level=1
  cp "$domain_dir/all_subdomains_level_1.txt" "$domain_dir/all_subdomains_current.txt"

  # Multi-level brute force subdomain enumeration with gobuster
  while [ "$current_level" -le "$max_depth" ]; do
    echo "[*] Brute forcing level $current_level for $domain"
    new_file="$domain_dir/all_subdomains_level_${current_level}_bruteforce.txt"
    > "$new_file"

    for wlist in "${subdomain_wordlists[@]}"; do
      while read -r sub; do
        gobuster dns -d "$sub" -w "$wlist" -i -q -o temp_gobuster.txt || true
        grep "Found:" temp_gobuster.txt | awk '{print $2}' >> "$new_file"
      done < "$domain_dir/all_subdomains_current.txt"
    done

    if [[ ! -s "$new_file" ]]; then
      echo "[*] No new subdomains found at level $current_level."
      break
    fi

    sort -u "$new_file" > "${new_file}.uniq"
    mv "${new_file}.uniq" "$new_file"

    cat "$domain_dir/all_subdomains_current.txt" "$new_file" | sort -u > "$domain_dir/all_subdomains_next.txt"
    mv "$domain_dir/all_subdomains_next.txt" "$domain_dir/all_subdomains_current.txt"

    current_level=$((current_level + 1))
  done

  mv "$domain_dir/all_subdomains_current.txt" "$domain_dir/all_subdomains_final.txt"

  # Resolve subdomains to IPs
  echo "[*] Resolving IPs for $domain"
  > "$domain_dir/subdomains_with_ips.txt"
  while read -r sub_domain; do
    ip=$(host "$sub_domain" 2>/dev/null | grep "has address" | awk '{print $4}' | head -n1)
    if [[ -n "$ip" ]]; then
      echo "$sub_domain $ip" >> "$domain_dir/subdomains_with_ips.txt"
    fi
  done < "$domain_dir/all_subdomains_final.txt"

  # Nmap scan
  echo "[*] Running Nmap for $domain"
  while read -r sub ip; do
    if [[ -n "$ip" ]]; then
      nmap -sV -sS -Pn -T4 -oN "$domain_dir/nmap/${sub}_nmap.txt" "$ip" || true
    fi
  done < "$domain_dir/subdomains_with_ips.txt"

  # CloudHunter enumeration
  echo "[*] Running CloudHunter on $domain"
  mkdir -p "$domain_dir/cloudhunter"
  pushd "$cloudhunter_dir" >/dev/null || return 1
  while read -r sub_domain; do
    name=$(echo "$sub_domain" | tr '/:' '_')
    python3 cloudhunter.py -t 10 "http://$sub_domain" > "$domain_dir/cloudhunter/${name}_cloudhunter.txt" || true
  done < "$domain_dir/all_subdomains_final.txt"
  popd >/dev/null || return 1

  # Directory brute force with dirsearch
  echo "[*] Running directory brute forcing for $domain"
  for wlist in "${dir_wordlists[@]}"; do
    while read -r sub ip; do
      if [[ -n "$ip" ]]; then
        url="http://$sub"
        rpt_file="$domain_dir/dirsearch/${sub}_$(basename "$wlist").txt"
        dirsearch -u "$url" -w "$wlist" -e php,html,js,aspx -x 400,500 --plain-text-report="$rpt_file" || true
        grep -E " 200 | 302 | 403 " "$rpt_file" > "${rpt_file%.txt}_valid_endpoints.txt"
      fi
    done < "$domain_dir/subdomains_with_ips.txt"
  done

  # Nuclei vulnerability scanning
  echo "[*] Running Nuclei on $domain"
  if command -v nuclei &>/dev/null; then
    nuclei -l "$domain_dir/all_subdomains_final.txt" -t nuclei-templates/ -o "$domain_dir/nuclei/nuclei_results.txt" || true
  else
    echo "[!] Nuclei not found, skipping."
  fi

  # HTTP probing
  echo "[*] HTTP probing subdomains for $domain"
  if command -v httprobe &>/dev/null; then
    cat "$domain_dir/all_subdomains_final.txt" | httprobe > "$domain_dir/httprobe/live_subdomains.txt"
  else
    echo "[!] httprobe not found, skipping."
  fi

  echo "[*] Recon complete for $domain"
}

export -f run_domain_recon
export recon_root
export cloudhunter_dir
export subdomain_wordlists
export dir_wordlists
export max_depth

cat "$domain_file" | parallel --jobs "$(nproc)" run_domain_recon {}

echo "[*] All reconnaissance tasks completed. Results at $recon_root"
