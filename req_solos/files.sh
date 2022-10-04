#!/bin/bash
right=$(printf '\xE2\x9C\x94')
target=$1
out="output"
Usage() {
       echo -e "$green
       Usage: ./files.sh -f targets.txt
       "
       exit 1
      }
collect() {
echo "Total targets: $(wc -l $target | awk '{print $1}')\n"
cat $target | ./gauplus --random-agent --subs -t 5000 | ./anew -q waybackurls.txt
cat waybackurls.txt | cut -d"?" -f1 | cut -d"=" -f1 > filtered.txt
}
filter() {
echo "Filtering targets..."
grep -iaE "([^.]+)\.zip$|([^.]+)\.zip\.[0-9]+$|([^.]+)\.zip[0-9]+$|([^.]+)\.zip[a-z][A-Z][0-9]+$|([^.]+)\.zip\.[a-z][A-Z][0-9]+$|([^.]+)\.rar$|([^.]+)\.tar$|([^.]+)\.tar\.gz$|([^.]+)\.tgz$|([^.]+)\.sql$|([^.]+)\.db$|([^.]+)\.sqlite$|([^.]+)\.pgsql\.txt$|([^.]+)\.mysql\.txt$|([^.]+)\.gz$|([^.]+)\.config$|([^.]+)\.log$|([^.]+)\.bak$|([^.]+)\.backup$|([^.]+)\.bkp$|([^.]+)\.crt$|([^.]+)\.dat$|([^.]+)\.eml$|([^.]+)\.java$|([^.]+)\.lst$|([^.]+)\.key$|([^.]+)\.passwd$|([^.]+)\.pl$|([^.]+)\.pwd$|([^.]+)\.mysql-connect$|([^.]+)\.jar$|([^.]+)\.cfg$|([^.]+)\.dir$|([^.]+)\.orig$|([^.]+)\.bz2$|([^.]+)\.old$|([^.]+)\.vbs$|([^.]+)\.img$|([^.]+)\.inf$|([^.]+)\.sh$|([^.]+)\.py$|([^.]+)\.vbproj$|([^.]+)\.mysql-pconnect$|([^.]+)\.war$|([^.]+)\.go$|([^.]+)\.psql$|([^.]+)\.sql\.gz$|([^.]+)\.vb$|([^.]+)\.webinfo$|([^.]+)\.jnlp$|([^.]+)\.cgi$|([^.]+)\.temp$|([^.]+)\.ini$|([^.]+)\.webproj$|([^.]+)\.xsql$|([^.]+)\.raw$|([^.]+)\.inc$|([^.]+)\.lck$|([^.]+)\.nz$|([^.]+)\.rc$|([^.]+)\.html\.gz$|([^.]+)\.gz$|([^.]+)\.env$|([^.]+)\.yml$" filtered.txt | sort -u | ./httpx -silent -follow-redirects -threads 800 -mc 200 > leaks.txt
rm filtered.txt
}
found() {
mkdir output 2> /dev/null
o=$(grep -aiE "([^.]+)\.zip$" leaks.txt | tee $out/zip.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀zip found.💀";fi
o=$(grep -aiE "([^.]+)\.zip\.[0-9]+$" leaks.txt | tee $out/zip.NUM.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀zip.NUM found.💀";fi
o=$(grep -aiE "([^.]+)\.zip[0-9]+$" leaks.txt | tee $out/zip_NUM.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀zip_NUM found.💀";fi
o=$(grep -aiE "([^.]+)\.zip[a-z][A-Z][0-9]+$" leaks.txt | tee $out/zip_alpha_ALPHA_NUM.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀zip_alpha_ALPHA_NUM found.💀";fi
o=$(grep -aiE "([^.]+)\.zip\.[a-z][A-Z][0-9]+$" leaks.txt | tee $out/zip.alpha_ALPHA_NUM.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀zip.alpha_ALPHA_NUM found.💀";fi
o=$(grep -aiE "([^.]+)\.rar$" leaks.txt | tee $out/rar.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀rar found.💀";fi
o=$(grep -aiE "([^.]+)\.tar$" leaks.txt | tee $out/tar.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀tar found.💀";fi
o=$(grep -aiE "([^.]+)\.tar\.gz$" leaks.txt | tee $out/tar.gz.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀tar.gz found.💀";fi
o=$(grep -aiE "([^.]+)\.tgz$" leaks.txt | tee $out/tgz.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀tgz found.💀";fi
o=$(grep -aiE "([^.]+)\.sql$" leaks.txt | tee $out/sql.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀sql found.💀";fi
o=$(grep -aiE "([^.]+)\.db$" leaks.txt | tee $out/db.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀db found.💀";fi
o=$(grep -aiE "([^.]+)\.sqlite$" leaks.txt | tee $out/sqlite.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀sqlite found.💀";fi
o=$(grep -aiE "([^.]+)\.pgsql\.txt$" leaks.txt | tee $out/pgsql.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀pgsql found.💀";fi
o=$(grep -aiE "([^.]+)\.mysql\.txt$" leaks.txt | tee $out/mysql.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀mysql found.💀";fi
o=$(grep -aiE "([^.]+)\.gz$" leaks.txt | tee $out/gz.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀gz found.💀";fi
o=$(grep -aiE "([^.]+)\.config$" leaks.txt | tee $out/config.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀config found.💀";fi
o=$(grep -aiE "([^.]+)\.log$" leaks.txt | tee $out/log.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀log found.💀";fi
o=$(grep -aiE "([^.]+)\.bak$" leaks.txt | tee $out/bak.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀bak found.💀";fi
o=$(grep -aiE "([^.]+)\.backup$" leaks.txt | tee $out/backup.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀backup found.💀";fi
o=$(grep -aiE "([^.]+)\.bkp$" leaks.txt | tee $out/bkp.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀bkp found.💀";fi
o=$(grep -aiE "([^.]+)\.crt$" leaks.txt | tee $out/crt.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀crt found.💀";fi
o=$(grep -aiE "([^.]+)\.dat$" leaks.txt | tee $out/dat.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀dat found.💀";fi
o=$(grep -aiE "([^.]+)\.eml$" leaks.txt | tee $out/eml.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀eml found.💀";fi
o=$(grep -aiE "([^.]+)\.java$" leaks.txt | tee $out/java.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀java found.💀";fi
o=$(grep -aiE "([^.]+)\.lst$" leaks.txt | tee $out/lst.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀lst found.💀";fi
o=$(grep -aiE "([^.]+)\.key$" leaks.txt | tee $out/key.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀key found.💀";fi
o=$(grep -aiE "([^.]+)\.passwd$" leaks.txt | tee $out/passwd.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀passwd found.💀";fi
o=$(grep -aiE "([^.]+)\.pl$" leaks.txt | tee $out/pl.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀pl found.💀";fi
o=$(grep -aiE "([^.]+)\.pwd$" leaks.txt | tee $out/pwd.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀pwd found.💀";fi
o=$(grep -aiE "([^.]+)\.mysql-connect$" leaks.txt | tee $out/mysql-connect.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀mysql-connect found.💀";fi
o=$(grep -aiE "([^.]+)\.jar$" leaks.txt | tee $out/jar.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀jar found.💀";fi
o=$(grep -aiE "([^.]+)\.cfg$" leaks.txt | tee $out/cfg.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀cfg found.💀";fi
o=$(grep -aiE "([^.]+)\.dir$" leaks.txt | tee $out/dir.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀dir found.💀";fi
o=$(grep -aiE "([^.]+)\.orig$" leaks.txt | tee $out/orig.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀orig found.💀";fi
o=$(grep -aiE "([^.]+)\.bz2$" leaks.txt | tee $out/bz2.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀bz2 found.💀";fi
o=$(grep -aiE "([^.]+)\.old$" leaks.txt | tee $out/old.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀old found.💀";fi
o=$(grep -aiE "([^.]+)\.vbs$" leaks.txt | tee $out/vbs.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀vbs found.💀";fi
o=$(grep -aiE "([^.]+)\.img$" leaks.txt | tee $out/img.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀img found.💀";fi
o=$(grep -aiE "([^.]+)\.inf$" leaks.txt | tee $out/inf.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀inf found.💀";fi
o=$(grep -aiE "([^.]+)\.sh$" leaks.txt | tee $out/sh.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀sh found.💀";fi
o=$(grep -aiE "([^.]+)\.py$" leaks.txt | tee $out/py.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀py found.💀";fi
o=$(grep -aiE "([^.]+)\.vbproj$" leaks.txt | tee $out/vbproj.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀vbproj found.💀";fi
o=$(grep -aiE "([^.]+)\.mysql-pconnect$" leaks.txt | tee $out/mysql-pconnect.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀mysql-pconnect found.💀";fi
o=$(grep -aiE "([^.]+)\.war$" leaks.txt | tee $out/war.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀war found.💀";fi
o=$(grep -aiE "([^.]+)\.go$" leaks.txt | tee $out/go.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀go found.💀";fi
o=$(grep -aiE "([^.]+)\.psql$" leaks.txt | tee $out/psql.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀psql found.💀";fi
o=$(grep -aiE "([^.]+)\.sql\.gz$" leaks.txt | tee $out/sql.gz.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀sql.gz found.💀";fi
o=$(grep -aiE "([^.]+)\.vb$" leaks.txt | tee $out/vb.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀vb found.💀";fi
o=$(grep -aiE "([^.]+)\.webinfo$" leaks.txt | tee $out/webinfo.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀webinfo found.💀";fi
o=$(grep -aiE "([^.]+)\.jnlp$" leaks.txt | tee $out/jnlp.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀jnlp found.💀";fi
o=$(grep -aiE "([^.]+)\.cgi$" leaks.txt | tee $out/cgi.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀cgi found.💀";fi
o=$(grep -aiE "([^.]+)\.temp$" leaks.txt | tee $out/temp.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀temp found.💀";fi
o=$(grep -aiE "([^.]+)\.ini$" leaks.txt | tee $out/ini.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀ini found.💀";fi
o=$(grep -aiE "([^.]+)\.webproj$" leaks.txt | tee $out/webproj.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀webproj found.💀";fi
o=$(grep -aiE "([^.]+)\.xsql$" leaks.txt | tee $out/xsql.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀xsql found.💀";fi
o=$(grep -aiE "([^.]+)\.raw$" leaks.txt | tee $out/raw.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀raw found.💀";fi
o=$(grep -aiE "([^.]+)\.inc$" leaks.txt | tee $out/inc.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀inc found.💀";fi
o=$(grep -aiE "([^.]+)\.lck$" leaks.txt | tee $out/lck.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀lck found.💀";fi
o=$(grep -aiE "([^.]+)\.nz$" leaks.txt | tee $out/nz.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀nz found.💀";fi
o=$(grep -aiE "([^.]+)\.rc$" leaks.txt | tee $out/rc.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀rc found.💀";fi
o=$(grep -aiE "([^.]+)\.html\.gz$" leaks.txt | tee $out/html.gz.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀html.gz found.💀";fi
o=$(grep -aiE "([^.]+)\.gz$" leaks.txt | tee $out/gz.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀gz found.💀";fi
o=$(grep -aiE "([^.]+)\.env$" leaks.txt | tee $out/env.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀env found.💀";fi
o=$(grep -aiE "([^.]+)\.yml$" leaks.txt | tee $out/yml.txt | wc -l);if [[ $o -gt 0 ]];then echo -e "💀yml found.💀";fi
find output/ -type f -empty -delete
}
target=False
list=(
        collect
        filter
        found
)
while [ -n "$1" ]; do
                case "$1" in
                        -f | --file)
                                target=$2
                                shift
                                ;;
                        *)
                                echo -e $red"[-]" "Unknown Option: $1"
                                Usage
                                ;;
                esac
        shift
done
[[ $target == "False" ]] && { echo -e $red"[-]" "Argument: -f/--file targets.txt missing."
Usage
}
(
        collect
        filter 
        found
)