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
echo "Web Heck Scanner, created by Graham Zemel (grahamzemel.com)"

echo "Starting the following sequence:"
echo "--Run Nikto--"
echo "--Get subdomains--"
echo "--Run Sqlmap heristic test--"
echo "--Run Nuclei--"
echo "--Filter filetypes--"
echo "--Clean up directory--"
echo "--Profit!--"
#Make proj config stuff run nikto on site
#if current directory contains $name as a folder, delete a folder with the same name
if [ -d "$name" ]; then
        rm -rf $name
fi
mkdir $name
echo ""
echo "----INITAL CONFIGURATION COMPLETE----"
echo "----COMMENCING NIKTO SCAN ~10m----"
"nikto/program/nikto.pl" -url $url -maxtime 10m > "${name}/niktoScan.txt"
}
getSubdomains() { #roughly 30 seconds
echo "----COLLECTING SUBDOMAINS ~30s----"
#upon killing this command, log the error and continue
"req_solos/gau" --threads 10 --subs $url > "${name}/liveSubs.txt" & 
sleep 30 
kill $!
if [ -s "${name}/liveSubs.txt" ]; then
        echo "Subdomains found!"
        cat "${name}/liveSubs.txt" | head -n 1000 > "${name}/liveSubs1000.txt"
        rm "${name}/liveSubs.txt"
        echo "Success! Total targets: $(wc -l ${name}/liveSubs1000.txt | awk '{print $1}') (yes, it is supposed to show the 'Terminated message'.)"
        cat "${name}/liveSubs1000.txt" | "req_solos/gauplus" —random-agent —subs -t 5000 | "req_solos/anew" -q "${name}/subsToFilter.txt"
        cat "${name}/subsToFilter.txt" | cut -d"?" -f1 | cut -d"=" -f1 > "${name}/filtered.txt"
else
        echo "No subdomains found!"
        rm -rf "${name}/nucleiResults.txt"
fi

}
# In case anyone's wondering, I can't swap sqlmapRun and nucleiRun's locations b/c some file error comes up that I don't have the energy to fix
# It works though, so I'm not gonna touch it (in true programmer fashion) -GZ
sqlmapRun(){ #instant
echo "----RUNNING SQLMAP ~instant-10m----"
echo "Running heuristic test (POSITIVE if 'Completed' not displayed within 5 seconds)"
"sqlmap/sqlmap.py" --level 3 --risk 3 --batch --eta --smart -url $url > "${name}/sqlVuln.txt"
echo "Completed heuristic test"
}
nucleiRun(){ #roughly 10 mins depending on site size
echo "----RUNNING NUCLEI ~1m-10m----"
"nuclei/nuclei" -as -es info -l "${name}/liveSubs1000.txt" -stats -si 30 -silent > "${name}/nucleiResults.txt"
if [ -s "${name}/nucleiResults.txt" ]; then
        echo "----LOCATED VULNERABILITIES----"
else
        echo "----NO VULNERABILITIES FOUND----"
        rm -rf "${name}/nucleiResults.txt"
fi
}
filterAndClean() { #instant
echo "----FILTERING FILETYPES ~instant----"
grep -iaE "([^.]+)\.zip$|([^.]+)\.zip\.[0-9]+$|([^.]+)\.zip[0-9]+$|([^.]+)\.zip[a-z][A-Z][0-9]+$|([^.]+)\.zip\.[a-z][A-Z][0-9]+$|([^.]+)\.rar$|([^.]+)\.tar$|([^.]+)\.tar\.gz$|([^.]+)\.tgz$|([^.]+)\.sql$|([^.]+)\.db$|([^.]+)\.sqlite$|([^.]+)\.pgsql\.txt$|([^.]+)\.mysql\.txt$|([^.]+)\.gz$|([^.]+)\.config$|([^.]+)\.log$|([^.]+)\.bak$|([^.]+)\.backup$|([^.]+)\.bkp$|([^.]+)\.crt$|([^.]+)\.dat$|([^.]+)\.eml$|([^.]+)\.java$|([^.]+)\.lst$|([^.]+)\.key$|([^.]+)\.passwd$|([^.]+)\.pl$|([^.]+)\.pwd$|([^.]+)\.mysql-connect$|([^.]+)\.jar$|([^.]+)\.cfg$|([^.]+)\.dir$|([^.]+)\.orig$|([^.]+)\.bz2$|([^.]+)\.old$|([^.]+)\.vbs$|([^.]+)\.img$|([^.]+)\.inf$|([^.]+)\.sh$|([^.]+)\.py$|([^.]+)\.vbproj$|([^.]+)\.mysql-pconnect$|([^.]+)\.war$|([^.]+)\.go$|([^.]+)\.psql$|([^.]+)\.sql\.gz$|([^.]+)\.vb$|([^.]+)\.webinfo$|([^.]+)\.jnlp$|([^.]+)\.cgi$|([^.]+)\.temp$|([^.]+)\.ini$|([^.]+)\.webproj$|([^.]+)\.xsql$|([^.]+)\.raw$|([^.]+)\.inc$|([^.]+)\.lck$|([^.]+)\.nz$|([^.]+)\.rc$|([^.]+)\.html\.gz$|([^.]+)\.gz$|([^.]+)\.env$|([^.]+)\.yml$" $name/filtered.txt | sort -u | "req_solos/httpx" -silent -follow-redirects -threads 800 -mc 200 > "${name}/leaks.txt"
rm -rf "${name}/filtered.txt" "${name}/liveSubs1000.txt" "${name}/subsToFilter.txt" "${name}/critUrls.txt"
}
cleanLeaks() { #instant
mkdir "${name}/output" 2> /dev/null
echo "----CLEANING LEAKS ~instant----"
o=$(grep -aiE "([^.]+)\.zip$" ${name}/leaks.txt | tee ${name}/output/zip.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀zip found.💀";fi
o=$(grep -aiE "([^.]+)\.zip\.[0-9]+$" ${name}/leaks.txt | tee ${name}/output/zip.NUM.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀zip.NUM found.💀";fi
o=$(grep -aiE "([^.]+)\.zip[0-9]+$" ${name}/leaks.txt | tee ${name}/output/zip_NUM.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀zip_NUM found.💀";fi
o=$(grep -aiE "([^.]+)\.zip[a-z][A-Z][0-9]+$" ${name}/leaks.txt | tee ${name}/output/zip_alpha_ALPHA_NUM.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀zip_alpha_ALPHA_NUM found.💀";fi
o=$(grep -aiE "([^.]+)\.zip\.[a-z][A-Z][0-9]+$" ${name}/leaks.txt | tee ${name}/output/zip.alpha_ALPHA_NUM.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀zip.alpha_ALPHA_NUM found.💀";fi
o=$(grep -aiE "([^.]+)\.rar$" ${name}/leaks.txt | tee ${name}/output/rar.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀rar found.💀";fi
o=$(grep -aiE "([^.]+)\.tar$" ${name}/leaks.txt | tee ${name}/output/tar.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀tar found.💀";fi
o=$(grep -aiE "([^.]+)\.tar\.gz$" ${name}/leaks.txt | tee ${name}/output/tar.gz.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀tar.gz found.💀";fi
o=$(grep -aiE "([^.]+)\.tgz$" ${name}/leaks.txt | tee ${name}/output/tgz.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀tgz found.💀";fi
o=$(grep -aiE "([^.]+)\.sql$" ${name}/leaks.txt | tee ${name}/output/sql.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀sql found.💀";fi
o=$(grep -aiE "([^.]+)\.db$" ${name}/leaks.txt | tee ${name}/output/db.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀db found.💀";fi
o=$(grep -aiE "([^.]+)\.sqlite$" ${name}/leaks.txt | tee ${name}/output/sqlite.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀sqlite found.💀";fi
o=$(grep -aiE "([^.]+)\.pgsql\.txt$" ${name}/leaks.txt | tee ${name}/output/pgsql.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀pgsql found.💀";fi
o=$(grep -aiE "([^.]+)\.mysql\.txt$" ${name}/leaks.txt | tee ${name}/output/mysql.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀mysql found.💀";fi
o=$(grep -aiE "([^.]+)\.gz$" ${name}/leaks.txt | tee ${name}/output/gz.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀gz found.💀";fi
o=$(grep -aiE "([^.]+)\.config$" ${name}/leaks.txt | tee ${name}/output/config.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀config found.💀";fi
o=$(grep -aiE "([^.]+)\.log$" ${name}/leaks.txt | tee ${name}/output/log.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀log found.💀";fi
o=$(grep -aiE "([^.]+)\.bak$" ${name}/leaks.txt | tee ${name}/output/bak.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀bak found.💀";fi
o=$(grep -aiE "([^.]+)\.backup$" ${name}/leaks.txt | tee ${name}/output/backup.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀backup found.💀";fi
o=$(grep -aiE "([^.]+)\.bkp$" ${name}/leaks.txt | tee ${name}/output/bkp.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀bkp found.💀";fi
o=$(grep -aiE "([^.]+)\.crt$" ${name}/leaks.txt | tee ${name}/output/crt.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀crt found.💀";fi
o=$(grep -aiE "([^.]+)\.dat$" ${name}/leaks.txt | tee ${name}/output/dat.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀dat found.💀";fi
o=$(grep -aiE "([^.]+)\.eml$" ${name}/leaks.txt | tee ${name}/output/eml.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀eml found.💀";fi
o=$(grep -aiE "([^.]+)\.java$" ${name}/leaks.txt | tee ${name}/output/java.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀java found.💀";fi
o=$(grep -aiE "([^.]+)\.lst$" ${name}/leaks.txt | tee ${name}/output/lst.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀lst found.💀";fi
o=$(grep -aiE "([^.]+)\.key$" ${name}/leaks.txt | tee ${name}/output/key.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀key found.💀";fi
o=$(grep -aiE "([^.]+)\.passwd$" ${name}/leaks.txt | tee ${name}/output/passwd.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀passwd found.💀";fi
o=$(grep -aiE "([^.]+)\.pl$" ${name}/leaks.txt | tee ${name}/output/pl.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀pl found.💀";fi
o=$(grep -aiE "([^.]+)\.pwd$" ${name}/leaks.txt | tee ${name}/output/pwd.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀pwd found.💀";fi
o=$(grep -aiE "([^.]+)\.mysql-connect$" ${name}/leaks.txt | tee ${name}/output/mysql-connect.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀mysql-connect found.💀";fi
o=$(grep -aiE "([^.]+)\.jar$" ${name}/leaks.txt | tee ${name}/output/jar.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀jar found.💀";fi
o=$(grep -aiE "([^.]+)\.cfg$" ${name}/leaks.txt | tee ${name}/output/cfg.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀cfg found.💀";fi
o=$(grep -aiE "([^.]+)\.dir$" ${name}/leaks.txt | tee ${name}/output/dir.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀dir found.💀";fi
o=$(grep -aiE "([^.]+)\.orig$" ${name}/leaks.txt | tee ${name}/output/orig.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀orig found.💀";fi
o=$(grep -aiE "([^.]+)\.bz2$" ${name}/leaks.txt | tee ${name}/output/bz2.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀bz2 found.💀";fi
o=$(grep -aiE "([^.]+)\.old$" ${name}/leaks.txt | tee ${name}/output/old.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀old found.💀";fi
o=$(grep -aiE "([^.]+)\.vbs$" ${name}/leaks.txt | tee ${name}/output/vbs.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀vbs found.💀";fi
o=$(grep -aiE "([^.]+)\.img$" ${name}/leaks.txt | tee ${name}/output/img.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀img found.💀";fi
o=$(grep -aiE "([^.]+)\.inf$" ${name}/leaks.txt | tee ${name}/output/inf.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀inf found.💀";fi
o=$(grep -aiE "([^.]+)\.sh$" ${name}/leaks.txt | tee ${name}/output/sh.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀sh found.💀";fi
o=$(grep -aiE "([^.]+)\.py$" ${name}/leaks.txt | tee ${name}/output/py.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀py found.💀";fi
o=$(grep -aiE "([^.]+)\.vbproj$" ${name}/leaks.txt | tee ${name}/output/vbproj.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀vbproj found.💀";fi
o=$(grep -aiE "([^.]+)\.mysql-pconnect$" ${name}/leaks.txt | tee ${name}/output/mysql-pconnect.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀mysql-pconnect found.💀";fi
o=$(grep -aiE "([^.]+)\.war$" ${name}/leaks.txt | tee ${name}/output/war.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀war found.💀";fi
o=$(grep -aiE "([^.]+)\.go$" ${name}/leaks.txt | tee ${name}/output/go.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀go found.💀";fi
o=$(grep -aiE "([^.]+)\.psql$" ${name}/leaks.txt | tee ${name}/output/psql.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀psql found.💀";fi
o=$(grep -aiE "([^.]+)\.sql\.gz$" ${name}/leaks.txt | tee ${name}/output/sql.gz.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀sql.gz found.💀";fi
o=$(grep -aiE "([^.]+)\.vb$" ${name}/leaks.txt | tee ${name}/output/vb.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀vb found.💀";fi
o=$(grep -aiE "([^.]+)\.webinfo$" ${name}/leaks.txt | tee ${name}/output/webinfo.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀webinfo found.💀";fi
o=$(grep -aiE "([^.]+)\.jnlp$" ${name}/leaks.txt | tee ${name}/output/jnlp.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀jnlp found.💀";fi
o=$(grep -aiE "([^.]+)\.cgi$" ${name}/leaks.txt | tee ${name}/output/cgi.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀cgi found.💀";fi
o=$(grep -aiE "([^.]+)\.temp$" ${name}/leaks.txt | tee ${name}/output/temp.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀temp found.💀";fi
o=$(grep -aiE "([^.]+)\.ini$" ${name}/leaks.txt | tee ${name}/output/ini.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀ini found.💀";fi
o=$(grep -aiE "([^.]+)\.webproj$" ${name}/leaks.txt | tee ${name}/output/webproj.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀webproj found.💀";fi
o=$(grep -aiE "([^.]+)\.xsql$" ${name}/leaks.txt | tee ${name}/output/xsql.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀xsql found.💀";fi
o=$(grep -aiE "([^.]+)\.raw$" ${name}/leaks.txt | tee ${name}/output/raw.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀raw found.💀";fi
o=$(grep -aiE "([^.]+)\.inc$" ${name}/leaks.txt | tee ${name}/output/inc.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀inc found.💀";fi
o=$(grep -aiE "([^.]+)\.nz$" ${name}/leaks.txt | tee ${name}/output/nz.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀nz found.💀";fi
o=$(grep -aiE "([^.]+)\.rc$" ${name}/leaks.txt | tee ${name}/output/rc.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀rc found.💀";fi
o=$(grep -aiE "([^.]+)\.html\.gz$" ${name}/leaks.txt | tee ${name}/output/html.gz.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀html.gz found.💀";fi
o=$(grep -aiE "([^.]+)\.gz$" ${name}/leaks.txt | tee ${name}/output/gz.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀gz found.💀";fi
o=$(grep -aiE "([^.]+)\.env$" ${name}/leaks.txt | tee ${name}/output/env.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀env found.💀";fi
o=$(grep -aiE "([^.]+)\.yml$" ${name}/leaks.txt | tee ${name}/output/yml.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀yml found.💀";fi
find "${name}/output/" -type f -empty -delete
echo -e "----FINISHED, VISIT ${name}/ for results----"
exit 0
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