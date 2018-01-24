#!/usr/bin/python3
#coding: utf-8

import socket
import optparse
import requests
import sys
import time
import struct
import os

limpar = 'clear'

parser = optparse.OptionParser()
parser.add_option('--duvida',help='Caso ainda estiver com duvida use o --duvida help',dest='ajuda')
parser.add_option('-u','--url',help='Lista diretorios existentes naquele site,',dest='site',metavar='site')
parser.add_option('-D','--admin',help='Procura a pagina de login.',dest='admin',metavar='site')
parser.add_option('-S',help='Scan de portas.',dest='scan',metavar='site')
parser.add_option('-R',help='Pacotes rodando na rede TCP,ICMP',dest='rede',metavar='Protocol')
(options, args) = parser.parse_args()


def help():
	print('''\033[33m
                        _____      ____
                       |  ___|   _/ ___|  ___ __ _ _ __
                       | |_ | | | \___ \ / __/ _` | '_ \
                       |  _|| |_| |___) | (_| (_| | | | |
                       |_|   \__, |____/ \___\__,_|_| |_|
                             |___/ \033[1;m
                                    		\033[43mv 1.1\033[1;m
                            \033[35mCriado por Fyk1ll\033[1;m

	\033[31m
Usage: scan.py [options]
Options:
  -h, --help            show this help message and exit
  -u testphp.vulnweb.com, --url=testphp.vulnweb.com
                        Lista diretorios existentes naquele site,
  -D admin, --admin=admin
                        Procura o admin
  -S site              Scan de portas
  -R Procotol          ICMP ou TCP
   Exemplos:
   			fyscan -u testphp.vulnweb.com
   			fyscan -D testphp.vulnweb.com
   			fyscan -S testphp.vulnweb.com
   			fyscan -u testphp.vulnweb.com > result.txt
   			fyscan -R icmp ou tcp
\033[1;m''')


def banner():
	print('''\033[35m
                        _____      ____
                       |  ___|   _/ ___|  ___ __ _ _ __
                       | |_ | | | \___ \ / __/ _` | '_ \
                       |  _|| |_| |___) | (_| (_| | | | |
                       |_|   \__, |____/ \___\__,_|_| |_|
                             |___/ \033[1;m
                                    		\033[43mv 1.1\033[1;m
		''')

def banner2():
	print('''\033[35m
                   ____            _   ____
                  |  _ \ ___  _ __| |_/ ___|  ___ __ _ _ __
                  | |_) / _ \| '__| __\___ \ / __/ _` | '_ \
                  |  __/ (_) | |  | |_ ___) | (_| (_| | | | |
                  |_|   \___/|_|   \__|____/ \___\__,_|_| |_|\033[1;m
                                                             \033[43mv 1.1\033[1;m

		''')

cabecalho = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36'}
meus_cookies = {'Ultima-visita': '20-05-2017',
				'Refer': 'www.google.com'}

if(len(sys.argv) < 1):
	help()
if options.ajuda:
	os.system(limpar)
	time.sleep(1)
	help()

if options.scan:
	os.system(limpar)
	banner2()
	time.sleep(2)
	ports = range(19, 3306)
	sitescan = options.scan
	for porta in ports:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(0.5)
		conexao =  s.connect_ex((sitescan, porta))
		if conexao == 0:
			print('\033[36m','[ NICE ] Porta aberta: ', (str(porta)), '\033[1;m')
		elif conexao == 11:
			print('\033[31m','[ WARNING ] Porta filtrada: ', (str(porta)), '\033[1;m')



if options.site:
	os.system(limpar)
	banner()
	if options.site[:8] == "https://" or options.site[:7] == "http://":
		print('Formato da URL invalido.\nNão utilize http:// ou https://')
		time.sleep(2)
		sys.exit()
	convert = ('http://' + options.site + '/')
	robots = (convert + 'robots.txt')
	result2 = []
	robotscheck = requests.get(robots)
	texto = requests.get(convert,
		headers=cabecalho,
		cookies=meus_cookies)
	print('Começou: ', time.strftime("%X %x %Z\n"))
	ipresult = socket.gethostbyname(options.site)
	print('IP do Alvo:',ipresult, '\n')
	lista = ['AJAX/', 'Flash', 'Flash/', 'images/', 'hpp/', 'pictures', 'pictures/', 'secured/', 'about/',
	'accessibility/', 'admin/', 'login.php', 'advertising/', 'accounts/', 'account', 'help/', 'alerts/', 'alert/', 'save/', 'store/', 'news/',
	'talk/', 'robots.txt', 'mail/', 'logs', 'capture/', 'search/', 'search.php','wp-content', 'wp-includes', 'index.php', 'wp-config.php',
	'index.html/', 'wp-login.php', 'wp-pass.php', 'wp-login.php', 'painel/login.php', 'test', 'test.html', 'bin', 'cache', 'components', 'layouts',
	'media/', 'tmp', 'templates', 'plugins', 'sitemap.xml', 'webmail/src/configtest.php', 'webmail/lib/emailreader_execute_on_each_page.inc.php',
	'htaccess.txt', 'config.php','doc', 'sistema', 'xmlrpc', 'missao', 'noticia', 'libraries', 'css', 'js', 'testes', 'upload', 'uploads', 'mailman/listinfo',
	'fotos', 'all', 'contact', 'error', 'index/', 'icons', 'resources', 'projects', 'project', 'Travel', 'agenda', 'agend', 'agent', 'apple', 'article', 'accept',
	'abusers', 'action', 'adlog', 'admbin', 'agency', 'acessorios', 'bytes', 'cookie', 'cookies', 'danger', 'cp', 'customers', 'decode', 'deface', 'device', 'dev', 'detalhe',
	'delete', 'view/', 'Cpanel/', 'result/', 'fonts', 'update.php', ]
	for nome in lista:
		try:
			scan = (convert + nome)
			scan1 = requests.get(scan,
				headers=cabecalho,
				cookies=meus_cookies)
			if scan1.status_code == 200:
				print('\033[31m','[+] RESP: 200: ',scan,'\033[1;m')
				result2.append(scan)
			else:
				print('\033[36m','[-] RESP: 404: ', scan,'\033[1;m')
			time.sleep(1.5)
		except KeyboardInterrupt:
			print('cancelou')
			exit()
	else:
		print('')


	texto = None

	if robotscheck.status_code == 200:
		print('\033[33m','[+] Verificando o robots.txt','\033[1;m')
		time.sleep(2)
		print('\n\n')
		texto = robotscheck.text
		print('\033[35m',texto,'\033[1;m')
	else:
		print('')
	print('Finalizou: ', time.strftime("%X %x %Z"))



if options.admin:
	os.system(limpar)
	banner()
	if options.admin[:8] == "https://" or options.admin[:7] == "http://":
		print('Formato da URL invalido.\nNão utilize http:// ou https://')
		time.sleep(2)
		sys.exit()
	convert1 = ('http://' + options.admin + '/')
	print('Começou: ', time.strftime("%X %x %Z\n"))
	texto1 = requests.get(convert1)
	admin = []
	ipresult = socket.gethostbyname(options.admin)
	print('IP do Alvo:',ipresult, '\n')
	lista1 = ['admin.php', 'admin.html', 'administrator','admin', 'cpanel', 'login.php', 'login.html','login/', '/admin/_login.php', 'painel/login.php', 'wp-admin', 'wp-login.php', 'admin/index.php',
	'admin/login.php', 'admin/login.aspx', 'paineldecontrole','adm/login.php/', 'administrator/login.php', 'cpanel/login.php', 'panel/login.php/', 'admin_area/login.php', 'adm', 'area/login.html',
	'login_admin/login.html', 'Cpanel/login.php','admin_login/', 'admin_index/', 'acceso.asp', 'admloginuser.asp', 'adm.php', 'admloginuser.aspx', 'adminpanel.php', 'admincontrol.php', 'adminLogin.php', 'adminLogin.js',
	'index.cgi', 'login.asp', 'webadmin/login.php','webadmin', 'webadmin/admin.php', 'webadmin/admin.html', 'panel-administracion/login.php', 'panel-administracion/login.js', 'panel-administracion/index.php', 'panel-administracion/index.html',
	'panel-administracion/admin.html', 'pages/admin/admin-login.js', 'pages/admin/admin-login.php', 'pages/admin/', 'openvpnadmin', 'nsw/admin/login.php', 'moderator.php', 'moderator/login.php', 'moderator.html',
	'moderator.asp', 'login-redirect/', 'loginsave/', 'administrator/login.html', 'adminLogin.php', 'adminLogin.html', 'admin/home.php', 'admin/home.html', 'adminarea/admin.html', 'admin_area/admin.html', 'adminarea/admin.php', 'admin_area/admin.php',
	'entrar.html', 'entrar.php', 'directadmin/', 'autologin/', 'administracao/', 'administrators', 'administrator/index.php', 'php.ini', '/Site/admin/login.php', 'admin/login/?destination=admin/login.php', 'ui/admin/login.php', 'admin/FCKeditor', 'adminapi', 'adminhtml', 'admins', 'adminpro',
	'Painel/Login.aspx', 'painel/login.aspx', 'admin/login/login.rails', 'admin/login.jsp', 'novo_admin/login.asp', 'admin.asp', 'paineldecontrole/login.php', 'suporte/login.php', 'controle/login.asp', 'administrative/login.html', 'administrator/login.asp',
	'atualizar/login.asp', 'logar_admin/', 'root/login.html', 'root/login.asp', '"root/login.php', '3d/login.html', '3d/login.asp', '3d/login.php', 'intranet', 'paineldecontrole/login.html', 'painel_de_controle/login.html', 'painel_de_controle/login.asp',
	'admin_index/', 'configurar/', 'servidor/login.php', 'admin_index/login.php']
	time.sleep(1)
	falha = "Error" or "Erro" or "404" or "Página não encontrada." or "Erro 404"
	for administrator in lista1:
		try:
			scan2 = (convert1 + administrator)
			scan3 = requests.get(scan2,
				headers=cabecalho,
				cookies=meus_cookies)
			if scan3.status_code == 200:
			    if falha in scan3.text:
			        print('\033[36m',scan2, '>>>> Nada','\033[1;m')
			    else:
			        print('\033[31m',scan2, '>>>> Admin encontrado :D','\033[1;m')
			else:
			    print('\033[36m',scan2, '>>>> Nada','\033[1;m')
		except KeyboardInterrupt:
			print('Vc cancelou')
			exit()
	print('Finalizou: ', time.strftime("%X %x %Z"))
else:
	print('')
if options.rede == 'icmp' or options.rede == 'ICMP':
	try:
		while True:
			escutando = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

			escutando.bind(('', 0))

			pacote = escutando.recvfrom(10000)
			print('===================================================================================')
			numerico = struct.unpack('!BBHHHBBH4s4s', pacote[0][0:20])
			print('From:', pacote[1][0])
			print('Pacote: ', numerico)
			print('IP Version:', numerico[0] >> 4)
			print('TTL:', numerico[5])
			print('Protocolo:', numerico[6])
			print('Source IP:', socket.inet_ntoa(numerico[8]))
			print('Target IP:', socket.inet_ntoa(numerico[9]))
			time.sleep(0.1)
	except KeyboardInterrupt:
		print('Vc cancelou')
		exit()


if options.rede == 'tcp' or options.rede == 'TCP':
	try:
		while True:
			escutando = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

			escutando.bind(('', 0))

			pacote = escutando.recvfrom(10000)
			print('===================================================================================')
			numerico = struct.unpack('!BBHHHBBH4s4s', pacote[0][0:20])
			print('From:', pacote[1][0])
			print('Pacote: ', numerico)
			print('IP Version:', numerico[0] >> 4)
			print('TTL:', numerico[5])
			print('Protocolo:', numerico[6])
			print('Source IP:', socket.inet_ntoa(numerico[8]))
			print('Target IP:', socket.inet_ntoa(numerico[9]))
			time.sleep(0.1)
	except KeyboardInterrupt:
		print('Vc cancelou')
exit()