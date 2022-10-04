#!/bin/bash
#Created by Graham Zemel, 2022
#A compilation of tools like nikto, nuclei, sqlmap, and some other helper tools to scan websites.
#Informational vulnerabilities may be hidden in some cases, feel free to modify the commands.

name=$1
url=$2
templates=$3

Usage() { #instant
       echo -e "Usage: ||| ./webHeck.sh -n 'siteName' -u 'url' ||| (use full url with 'http(s)://', ex. https://google.com)"
       exit 1
}
niktoRun() { #maximum of 10 minutes
#Make proj config stuff run nikto on site
echo "$yellow Creating directories and running Nikto..."
mkdir $name 
cd $name
"nikto/program/nikto.pl" -url $url -maxtime 15m -output "${name}_niktoScan.txt"
}
getSubdomains() { #roughly 30 seconds
echo "$yellow Running gau to collect subdomains..."
"req_solos/gau" --threads 10 --subs $url > liveSubs.txt
echo "$yellow Total targets: $(wc -l liveSubs.txt | awk '{print $1}')..."
cat liveSubs.txt | "req_solos/gauplus" —random-agent —subs -t 5000 | "req_solos/anew" -q subsToFilter.txt
cat subsToFilter.txt | cut -d"?" -f1 | cut -d"=" -f1 > filtered.txt
}
sqlmapRun(){ #instant
echo "$yellow Running sqlmap..."
"sqlmap/sqlmap.py" --level 3 --risk 3 --batch -url $url  > sqlVuln.txt 
}
nucleiRun(){ #roughly 10 mins depending on site size
echo "$yellow Running Nuclei..."
"nuclei/nuclei" -as -es info -l liveSubs.txt -stats -si 10 -o nucleiResults.txt
if [ -s nucleiResults.txt ]; then
        echo "Found nuclei results!"
else
        rm -rf nucleiResults.txt
fi
}
filterAndClean() { #instant
echo "Filtering targets..."
grep -iaE "([^.]+)\.zip$|([^.]+)\.zip\.[0-9]+$|([^.]+)\.zip[0-9]+$|([^.]+)\.zip[a-z][A-Z][0-9]+$|([^.]+)\.zip\.[a-z][A-Z][0-9]+$|([^.]+)\.rar$|([^.]+)\.tar$|([^.]+)\.tar\.gz$|([^.]+)\.tgz$|([^.]+)\.sql$|([^.]+)\.db$|([^.]+)\.sqlite$|([^.]+)\.pgsql\.txt$|([^.]+)\.mysql\.txt$|([^.]+)\.gz$|([^.]+)\.config$|([^.]+)\.log$|([^.]+)\.bak$|([^.]+)\.backup$|([^.]+)\.bkp$|([^.]+)\.crt$|([^.]+)\.dat$|([^.]+)\.eml$|([^.]+)\.java$|([^.]+)\.lst$|([^.]+)\.key$|([^.]+)\.passwd$|([^.]+)\.pl$|([^.]+)\.pwd$|([^.]+)\.mysql-connect$|([^.]+)\.jar$|([^.]+)\.cfg$|([^.]+)\.dir$|([^.]+)\.orig$|([^.]+)\.bz2$|([^.]+)\.old$|([^.]+)\.vbs$|([^.]+)\.img$|([^.]+)\.inf$|([^.]+)\.sh$|([^.]+)\.py$|([^.]+)\.vbproj$|([^.]+)\.mysql-pconnect$|([^.]+)\.war$|([^.]+)\.go$|([^.]+)\.psql$|([^.]+)\.sql\.gz$|([^.]+)\.vb$|([^.]+)\.webinfo$|([^.]+)\.jnlp$|([^.]+)\.cgi$|([^.]+)\.temp$|([^.]+)\.ini$|([^.]+)\.webproj$|([^.]+)\.xsql$|([^.]+)\.raw$|([^.]+)\.inc$|([^.]+)\.lck$|([^.]+)\.nz$|([^.]+)\.rc$|([^.]+)\.html\.gz$|([^.]+)\.gz$|([^.]+)\.env$|([^.]+)\.yml$" filtered.txt | sort -u | "req_solos/httpx" -silent -follow-redirects -threads 800 -mc 200 > leaks.txt
rm -rf filtered.txt liveSubs.txt subsToFilter.txt critUrls.txt
}
cleanLeaks() { #instant
mkdir output 2> /dev/null
o=$(grep -aiE "([^.]+)\.zip$" leaks.txt | tee output/zip.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀zip found.💀";fi
o=$(grep -aiE "([^.]+)\.zip\.[0-9]+$" leaks.txt | tee output/zip.NUM.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀zip.NUM found.💀";fi
o=$(grep -aiE "([^.]+)\.zip[0-9]+$" leaks.txt | tee output/zip_NUM.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀zip_NUM found.💀";fi
o=$(grep -aiE "([^.]+)\.zip[a-z][A-Z][0-9]+$" leaks.txt | tee output/zip_alpha_ALPHA_NUM.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀zip_alpha_ALPHA_NUM found.💀";fi
o=$(grep -aiE "([^.]+)\.zip\.[a-z][A-Z][0-9]+$" leaks.txt | tee output/zip.alpha_ALPHA_NUM.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀zip.alpha_ALPHA_NUM found.💀";fi
o=$(grep -aiE "([^.]+)\.rar$" leaks.txt | tee output/rar.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀rar found.💀";fi
o=$(grep -aiE "([^.]+)\.tar$" leaks.txt | tee output/tar.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀tar found.💀";fi
o=$(grep -aiE "([^.]+)\.tar\.gz$" leaks.txt | tee output/tar.gz.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀tar.gz found.💀";fi
o=$(grep -aiE "([^.]+)\.tgz$" leaks.txt | tee output/tgz.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀tgz found.💀";fi
o=$(grep -aiE "([^.]+)\.sql$" leaks.txt | tee output/sql.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀sql found.💀";fi
o=$(grep -aiE "([^.]+)\.db$" leaks.txt | tee output/db.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀db found.💀";fi
o=$(grep -aiE "([^.]+)\.sqlite$" leaks.txt | tee output/sqlite.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀sqlite found.💀";fi
o=$(grep -aiE "([^.]+)\.pgsql\.txt$" leaks.txt | tee output/pgsql.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀pgsql found.💀";fi
o=$(grep -aiE "([^.]+)\.mysql\.txt$" leaks.txt | tee output/mysql.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀mysql found.💀";fi
o=$(grep -aiE "([^.]+)\.gz$" leaks.txt | tee output/gz.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀gz found.💀";fi
o=$(grep -aiE "([^.]+)\.config$" leaks.txt | tee output/config.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀config found.💀";fi
o=$(grep -aiE "([^.]+)\.log$" leaks.txt | tee output/log.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀log found.💀";fi
o=$(grep -aiE "([^.]+)\.bak$" leaks.txt | tee output/bak.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀bak found.💀";fi
o=$(grep -aiE "([^.]+)\.backup$" leaks.txt | tee output/backup.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀backup found.💀";fi
o=$(grep -aiE "([^.]+)\.bkp$" leaks.txt | tee output/bkp.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀bkp found.💀";fi
o=$(grep -aiE "([^.]+)\.crt$" leaks.txt | tee output/crt.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀crt found.💀";fi
o=$(grep -aiE "([^.]+)\.dat$" leaks.txt | tee output/dat.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀dat found.💀";fi
o=$(grep -aiE "([^.]+)\.eml$" leaks.txt | tee output/eml.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀eml found.💀";fi
o=$(grep -aiE "([^.]+)\.java$" leaks.txt | tee output/java.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀java found.💀";fi
o=$(grep -aiE "([^.]+)\.lst$" leaks.txt | tee output/lst.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀lst found.💀";fi
o=$(grep -aiE "([^.]+)\.key$" leaks.txt | tee output/key.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀key found.💀";fi
o=$(grep -aiE "([^.]+)\.passwd$" leaks.txt | tee output/passwd.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀passwd found.💀";fi
o=$(grep -aiE "([^.]+)\.pl$" leaks.txt | tee output/pl.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀pl found.💀";fi
o=$(grep -aiE "([^.]+)\.pwd$" leaks.txt | tee output/pwd.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀pwd found.💀";fi
o=$(grep -aiE "([^.]+)\.mysql-connect$" leaks.txt | tee output/mysql-connect.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀mysql-connect found.💀";fi
o=$(grep -aiE "([^.]+)\.jar$" leaks.txt | tee output/jar.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀jar found.💀";fi
o=$(grep -aiE "([^.]+)\.cfg$" leaks.txt | tee output/cfg.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀cfg found.💀";fi
o=$(grep -aiE "([^.]+)\.dir$" leaks.txt | tee output/dir.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀dir found.💀";fi
o=$(grep -aiE "([^.]+)\.orig$" leaks.txt | tee output/orig.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀orig found.💀";fi
o=$(grep -aiE "([^.]+)\.bz2$" leaks.txt | tee output/bz2.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀bz2 found.💀";fi
o=$(grep -aiE "([^.]+)\.old$" leaks.txt | tee output/old.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀old found.💀";fi
o=$(grep -aiE "([^.]+)\.vbs$" leaks.txt | tee output/vbs.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀vbs found.💀";fi
o=$(grep -aiE "([^.]+)\.img$" leaks.txt | tee output/img.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀img found.💀";fi
o=$(grep -aiE "([^.]+)\.inf$" leaks.txt | tee output/inf.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀inf found.💀";fi
o=$(grep -aiE "([^.]+)\.sh$" leaks.txt | tee output/sh.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀sh found.💀";fi
o=$(grep -aiE "([^.]+)\.py$" leaks.txt | tee output/py.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀py found.💀";fi
o=$(grep -aiE "([^.]+)\.vbproj$" leaks.txt | tee output/vbproj.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀vbproj found.💀";fi
o=$(grep -aiE "([^.]+)\.mysql-pconnect$" leaks.txt | tee output/mysql-pconnect.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀mysql-pconnect found.💀";fi
o=$(grep -aiE "([^.]+)\.war$" leaks.txt | tee output/war.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀war found.💀";fi
o=$(grep -aiE "([^.]+)\.go$" leaks.txt | tee output/go.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀go found.💀";fi
o=$(grep -aiE "([^.]+)\.psql$" leaks.txt | tee output/psql.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀psql found.💀";fi
o=$(grep -aiE "([^.]+)\.sql\.gz$" leaks.txt | tee output/sql.gz.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀sql.gz found.💀";fi
o=$(grep -aiE "([^.]+)\.vb$" leaks.txt | tee output/vb.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀vb found.💀";fi
o=$(grep -aiE "([^.]+)\.webinfo$" leaks.txt | tee output/webinfo.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀webinfo found.💀";fi
o=$(grep -aiE "([^.]+)\.jnlp$" leaks.txt | tee output/jnlp.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀jnlp found.💀";fi
o=$(grep -aiE "([^.]+)\.cgi$" leaks.txt | tee output/cgi.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀cgi found.💀";fi
o=$(grep -aiE "([^.]+)\.temp$" leaks.txt | tee output/temp.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀temp found.💀";fi
o=$(grep -aiE "([^.]+)\.ini$" leaks.txt | tee output/ini.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀ini found.💀";fi
o=$(grep -aiE "([^.]+)\.webproj$" leaks.txt | tee output/webproj.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀webproj found.💀";fi
o=$(grep -aiE "([^.]+)\.xsql$" leaks.txt | tee output/xsql.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀xsql found.💀";fi
o=$(grep -aiE "([^.]+)\.raw$" leaks.txt | tee output/raw.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀raw found.💀";fi
o=$(grep -aiE "([^.]+)\.inc$" leaks.txt | tee output/inc.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀inc found.💀";fi
o=$(grep -aiE "([^.]+)\.lck$" leaks.txt | tee output/lck.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀lck found.💀";fi
o=$(grep -aiE "([^.]+)\.nz$" leaks.txt | tee output/nz.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀nz found.💀";fi
o=$(grep -aiE "([^.]+)\.rc$" leaks.txt | tee output/rc.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀rc found.💀";fi
o=$(grep -aiE "([^.]+)\.html\.gz$" leaks.txt | tee output/html.gz.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀html.gz found.💀";fi
o=$(grep -aiE "([^.]+)\.gz$" leaks.txt | tee output/gz.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀gz found.💀";fi
o=$(grep -aiE "([^.]+)\.env$" leaks.txt | tee output/env.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀env found.💀";fi
o=$(grep -aiE "([^.]+)\.yml$" leaks.txt | tee output/yml.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀yml found.💀";fi
find output/ -type f -empty -delete
}
list=(
        niktoRun
        getSubdomains
        nucleiRun
        sqlmapRun
        filterAndClean
        cleanLeaks
)

while getopts "n:u:t:" opt
do
   case "$opt" in
      n ) name="$OPTARG" ;;
      u ) url="$OPTARG" ;;
      t ) templates="$OPTARG" ;;
      ? ) Usage ;;
   esac
done

if [ -z "$name" ] || [ -z "$url" ] || [ -z "$templates" ]
then
   echo $red"[-]" "Some parameters/Options invalid";
   Usage
fi

niktoRun
getSubdomains
nucleiRun
sqlmapRun
filterAndClean
cleanLeaks