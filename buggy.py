#!usr/bin/env/python
#!usr/bin/env/python

from bs4 import BeautifulSoup
from urllib.parse import urlparse
import requests
import sys
import os
import atexit
import optparse
from http import cookies
requests.packages.urllib3.disable_warnings()

RED='\033[91m'
GREEN='\033[92m'
ORANGE='\033[93m'
COLOR1='\033[95m'
COLOR2='\033[96m'
RESET='\x1b[0m'

def getlink (url):
  try:

    if len(cookies) > 2:
      headers = {'Cookie': cookies}
      r = requests.get(url, headers=headers, verify=False)
    else:
      r  = requests.get(url, verify=False)

    data = r.text
    soup = BeautifulSoup(data, "lxml")
    parsed_uri = urlparse(url)
    domain = '{uri.netloc}'.format(uri=parsed_uri)
    domain = domain.split(':')[0]
  except Exception as ex:
    print(ex)

  urls = open("/tmp/" + domain + "_" + port + "-urls.txt","w+")
  urls_saved = open(save_dir + domain + "_" + port + "-urls.txt","a")
  forms_saved = open(save_dir + domain + "_" + port + "-forms.txt","a")
  dynamic_saved = open(save_dir + domain + "_" + port + "-dynamic.txt","a")
  emails_saved = open(save_dir + domain + "_" + port + "-emails.txt","a")
  phones_saved = open(save_dir + domain + "_" + port + "-phones.txt","a")
  subdomains_saved = open(save_dir + domain + "_" + port + "-subdomains.txt","a")

  print ("")
  print (GREEN + "==================================================================================================" + RESET)
  print (GREEN + url)
  print (GREEN + "==================================================================================================" + RESET)
  for form in soup.find_all('form'):
    forms_saved.write(url + "\n")

  
  for link in soup.find_all('a'):
    if link.get('href') is not None:
      parsed_uri = urlparse(link.get('href'))
      linkdomain = '{uri.netloc}'.format(uri=parsed_uri)
      if (domain != linkdomain) and (linkdomain != "") and (domain in linkdomain):
        print (COLOR1 + "[+] Sub-domain found! " + linkdomain + " " + RESET)
        subdomains_saved.write(linkdomain + "\n")
      if link.get('href')[:4] == "http":
        if domain in link.get('href'):
          if "?" in link.get('href'):
            print (RED + "[+] Dynamic URL found! " + link.get('href') + " " + RESET)
            urls.write(link.get('href') + "\n")
            urls_saved.write(link.get('href') + "\n")
            dynamic_saved.write(link.get('href') + "\n")
          else:
            print (link.get('href'))
            urls.write(link.get('href') + "\n")
            urls_saved.write(link.get('href') + "\n")
      elif "?" in link.get('href'):
        print (RED + "[+] Dynamic URL found! " + url + "/" + link.get('href') + " " + RESET)
        urls.write(url + "/" + link.get('href') + "\n")
        urls_saved.write(url + "/" + link.get('href') + "\n")
        dynamic_saved.write(url + "/" + link.get('href') + "\n")
      elif link.get('href')[:4] == "tel:":
        s = link.get('href')
        phonenum = s.split(':')[1]
        print (ORANGE + "[i] Telephone # found! " + phonenum + " " + RESET)
        phones_saved.write(phonenum + "\n")
      elif link.get('href')[:7] == "mailto:":
        s = link.get('href')
        email = s.split(':')[1]
        print (ORANGE + "[i] Email found! " + email + " " + RESET)
        emails_saved.write(email + "\n")
 
      else:
        print (url + "/" + link.get('href'))
        urls.write(url + "/" + link.get('href') + "\n")
        urls_saved.write(url + "/" + link.get('href') + "\n")
  print (GREEN + "__________________________________________________________________________________________________" + RESET)

def readfile():
  filename = "/tmp/" + domain + "_" + port + "-urls.txt"
  with open(filename) as f:
    urls = f.read().splitlines()
    for url in urls:
      try:
        getlink(url)
      except Exception as ex:
        print(ex)



def exit_handler():
  os.system('sort -u ' + save_dir + domain + "_" + port + '-urls.txt > ' + save_dir + domain + "_" + port + '-urls-sorted.txt 2>/dev/null')
  os.system('sort -u ' + save_dir + domain + "_" + port + '-forms.txt > ' + save_dir + domain + "_" + port + '-forms-sorted.txt 2>/dev/null')
  os.system('sort -u ' + save_dir + domain + "_" + port + '-dynamic.txt > ' + save_dir + domain + "_" + port + '-dynamic-sorted.txt 2>/dev/null')
  os.system('rm -f ' + save_dir + domain + "_" + port + '-dynamic-unique.txt 2>/dev/null')
  os.system('touch ' + save_dir + domain + "_" + port + '-dynamic-unique.txt')
  os.system('for a in `cat ' + save_dir + domain + "_" + port + '-dynamic-sorted.txt | cut -d \'?\' -f2 | sort -u | cut -d \'=\' -f1 | sort -u`; do for b in `egrep $a ' + save_dir + domain + "_" + port +'-dynamic.txt -m 1`; do echo $b >> ' + save_dir + domain + "_" + port + '-dynamic-unique.txt; done; done;')
  os.system('sort -u ' + save_dir + domain + "_" + port + '-subdomains.txt > ' + save_dir + domain + "_" + port + '-subdomains-sorted.txt 2>/dev/null')
  os.system('sort -u ' + save_dir + domain + "_" + port + '-emails.txt > ' + save_dir + domain + "_" + port + '-emails-sorted.txt 2>/dev/null')
  os.system('sort -u ' + save_dir + domain + "_" + port + '-phones.txt > ' + save_dir + domain + "_" + port + '-phones-sorted.txt 2>/dev/null')


  print (GREEN + "[+] URL's Discovered: \n" + save_dir + domain + "_" + port + "-urls-sorted.txt" + RESET)
  print (GREEN + "__________________________________________________________________________________________________" + RESET)
  os.system('cat ' + save_dir + domain + "_" + port + '-urls-sorted.txt')
  print (RESET)
  print (GREEN + "[+] Dynamic URL's Discovered: \n" + save_dir + domain + "_" + port + "-dynamic-sorted.txt" + RESET)
  print (GREEN + "__________________________________________________________________________________________________" + RESET)
  os.system('cat ' + save_dir + domain + "_" + port + '-dynamic-sorted.txt')
  print (RESET)
  print (GREEN + "[+] Form URL's Discovered: \n" + save_dir + domain + "_" + port + "-forms-sorted.txt" + RESET)
  print (GREEN + "__________________________________________________________________________________________________" + RESET)
  os.system('cat ' + save_dir + domain + "_" + port + '-forms-sorted.txt')
  print (RESET)
  print (GREEN + "[+] Unique Dynamic Parameters Discovered: \n" + save_dir + domain + "_" + port + "-dynamic-unique.txt" + RESET)
  print (GREEN + "__________________________________________________________________________________________________" + RESET)
  os.system('cat ' + save_dir + domain + "_" + port + '-dynamic-unique.txt')
  print (RESET)
  print (GREEN + "[+] Sub-domains Discovered: \n" + save_dir + domain + "_" + port + "-subdomains-sorted.txt" + RESET)
  print (GREEN + "__________________________________________________________________________________________________" + RESET)
  os.system('cat ' + save_dir + domain + "_" + port + '-subdomains-sorted.txt')
  print (RESET)
  print (GREEN + "[+] Emails Discovered: \n" + save_dir + domain + "_" + port + "-emails-sorted.txt" + RESET)
  print (GREEN + "__________________________________________________________________________________________________" + RESET)
  os.system('cat ' + save_dir + domain + "_" + port + '-emails-sorted.txt')
  print (RESET)
  print (GREEN + "[+] Phones Discovered: \n" + save_dir + domain + "_" + port + "-phones-sorted.txt" + RESET)
  print (GREEN + "__________________________________________________________________________________________________" + RESET)
  os.system('cat ' + save_dir + domain + "_" + port + '-phones-sorted.txt')
  print (RESET)
  print (RED + "[+] Loot Saved To: \n" + save_dir + RESET)
  print (RED + "__________________________________________________________________________________________________" + RESET)
  print (RESET)

  os.system('rm -f ' + save_dir + domain + "_" + port + '-dynamic.txt')
  os.system('rm -f ' + save_dir + domain + "_" + port + '-forms.txt')
  os.system('rm -f ' + save_dir + domain + "_" + port + '-emails.txt')
  os.system('rm -f ' + save_dir + domain + "_" + port + '-phones.txt')
  os.system('rm -f ' + save_dir + domain + "_" + port + '-urls.txt')
  os.system('rm -f ' + save_dir + domain + "_" + port + '-subdomains.txt')
  os.system('rm -f /tmp/' + domain + "_" + port + '-urls.txt 2> /dev/null')

  if scan == "y":
    os.system('for a in `cat ' + save_dir + domain + "_" + port + '-dynamic-unique.txt`; do python3 /usr/bin/injectx.py -u $a; done;')
  else:
    pass


globalURL = "globalBadness"
if len(sys.argv) < 2:
  print ("You need to specify a URL to scan. Use --help for all options.")
  quit()
else:
  parser = optparse.OptionParser()
  parser.add_option('-u', '--url',
                    action="store", dest="url",
                    help="Full URL to spider", default="")

  parser.add_option('-d', '--domain',
                    action="store", dest="domain",
                    help="Domain name to spider", default="")

  parser.add_option('-c', '--cookie',
                    action="store", dest="cookie",
                    help="Cookies to send", default="")

  parser.add_option('-l', '--level',
                    action="store", dest="level",
                    help="Level of depth to traverse", default="2")

  parser.add_option('-s', '--scan',
                    action="store", dest="scan",
                    help="Scan all dynamic URL's found", default="n")

  parser.add_option('-p', '--port',
                    action="store", dest="port",
                    help="Port for the URL", default="80")

  parser.add_option('-v', '--verbose',
                    action="store", dest="verbose",
                    help="Set verbose mode ON", default="y")

  options, args = parser.parse_args()
  target = str(options.url)
  domain = str(options.domain)
  cookies = str(options.cookie)
  max_depth = str(options.level)
  scan = str(options.scan)
  port = str(options.port)
  verbose = str(options.verbose)
  ans = scan
  level = 1

 
  if ":" not in target:

    if len(str(target)) > 6:
      url = target + ":" + port  

    else:
      url = "http://" + str(domain) + ":" + port

    if len(str(domain)) > 4:
      target = "http://" + domain + ":" + port
    else:
      print (target)
      urlparse(target)
      parsed_uri = urlparse(target)
      domain = '{uri.netloc}'.format(uri=parsed_uri)

  else:
    url = target
    globalURL = target
    parsed_uri = urlparse(target)
    domainWithPort = '{uri.netloc}'.format(uri=parsed_uri)
    domain = domainWithPort.split(':')[0]
    if (len(target.split(':')) > 2):
      portWithPossiblePath = target.split(':')[2]
      port = portWithPossiblePath.split('/')[0]
    else:
      port = port

  save_dir = "/usr/share/buggy/" + domain + "_" + port + "/"
  os.system('mkdir -p ' + save_dir + ' 2>/dev/null')
  atexit.register(exit_handler)


  
  urls_file = "/tmp/" + domain + "_" + port + "-urls.txt"
  urls_saved_file = save_dir + domain + "_" + port + "-urls.txt"
  forms_saved_file = save_dir + domain + "_" + port + "-forms.txt"
  subdomain_file = save_dir + domain + "_" + port + "-subdomains.txt"
  emails_file = save_dir + domain + "_" + port + "-emails.txt"
  phones_file = save_dir + domain + "_" + port + "-phones.txt"
  urls = open(urls_file,"w+")
  urls.close()
  urls_saved = open(urls_saved_file,"w+")
  urls_saved.close()
  forms_saved = open(forms_saved_file,"w+")
  forms_saved.close()
  subdomains = open(subdomain_file,"w+")
  subdomains.close()
  emails = open(emails_file,"w+")
  emails.close()
  phones = open(phones_file,"w+")
  phones.close()


  try:
    getlink(url)
  except Exception as ex:
    print(ex)

  while (int(level) <= int(max_depth)):
    level = level+1
    if (int(level) <= int(max_depth)):
      try:
        readfile()
      except Exception as ex:
        print(ex)
    else:
      break
