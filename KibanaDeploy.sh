#!/bin/bash
#----------------------------------------------------------------------
# Script Setup ELK on debian systems 
# Created by De Lucia Francesco
#      v yyyy mmdd
# Ver. 1.2016.0608
#----------------------------------------------------------------------
# Set up values.
#----------------------------------------------------------------------
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo ""
echo "Script Setup ELK on debian systems" 
echo "Created by De Lucia Francesco"
echo "Ver. 1.2016.0608"
echo ""
echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

JDK_Ver=8
IP_ELK=127.0.0.1

KIBANA_FILE=kibana.yml
KIBANA_PATH=/opt/kibana/config
KIBANA_CONF=$KIBANA_PATH/$KIBANA_FILE
#KIBANA_CONF=$KIBANA_FILE
KIBANA_ADMIN_USER=Kadmin
KIBANA_VER=4.5

ELASTIC_VERSION=2.x
ELASTIC_FILE=elasticsearch.yml
ELASTIC_PATH=/etc/elasticsearch
ELASTIC_CONF=$ELASTIC_PATH/$ELASTIC_FILE
#ELASTIC_CONF=$ELASTIC_FILE

NGINIX_FILE=default
NGINIX_PATH=/etc/nginx/sites-available
NGINIX_PATH_CONFD=/etc/nginx/conf.d
NGINIX_CONF=$NGINIX_PATH/$NGINIX_FILE
#NGINIX_CONF=$NGINIX_FILE

OPENSSL_FILE=openssl.cnf
OPENSSL_PATH=/etc/ssl

OPENSSL_CONF=$OPENSSL_PATH/$OPENSSL_FILE

PKI_PATH=/etc/pki/tls
PKI_KEY=logstash-forwarder.key
PKI_CERT=logstash-forwarder.crt

PKI_PATH_CERT=${PKI_PATH}/certs/$PKI_CERT
PKI_PATH_KEY=${PKI_PATH}/private/$PKI_KEY


#OPENSSL_CONF=$OPENSSL_FILE

LOGSTASH_VERSION=2.x
LOGSTASH_CONF_PATH=/etc/logstash/conf.d
LOGSTASH_SYSLOG_FILE=10-filter.conf
LOGSTASH_CONF_FILE=02-input.conf
LOGSTASH_ELASTICSEARCH_FILE=30-output.conf
LOGSTASH_ELASTICSEARCH_ALL=all.conf

LOGSTASH_CONF=$LOGSTASH_CONF_PATH/$LOGSTASH_ELASTICSEARCH_ALL
LOGSTASH_SYSLOG=$LOGSTASH_CONF_PATH/$LOGSTASH_SYSLOG_FILE
LOGSTASH_ELASTICSEARCH=$LOGSTASH_CONF_PATH/$LOGSTASH_ELASTICSEARCH_FILE


# A menu driven shell script sample template 
## ----------------------------------
# Step #1: Define variables
# ----------------------------------
EDITOR=vim
PASSWD=/etc/passwd
RED='\033[0;41;30m'
STD='\033[0;0;39m'
 
CreateKibanaConfiguration() {
	echo "#################################################################"
	echo "Crea configurazione Kibana"
	echo "#################################################################"
	if [ -a "$KIBANA_CONF.old" ]
	then
	   echo "File $KIBANA_CONF.old esiste"
	else
	  echo "File $KIBANA_CONF.old non esiste"
	  if [ -a "$KIBANA_CONF" ] 
	  then 
	  	cp $KIBANA_CONF $KIBANA_CONF.old
	  fi
	fi

cat > $KIBANA_CONF << EOF
	# Kibana is served by a back end server. This controls which port to use.
	# server.port: 5601
	# The host to bind the server to.
	# server.host: "0.0.0.0"
	server.host: "localhost"
	# If you are running kibana behind a proxy, and want to mount it at a path,
	# specify that path here. The basePath can't end in a slash.
	# server.basePath: ""
	# The maximum payload size in bytes on incoming server requests.
	# server.maxPayloadBytes: 1048576

	# kibana.index: ".kibana"
	# The default application to load.
	# kibana.defaultAppId: "discover"
	# If your Elasticsearch is protected with basic auth, these are the user credentials
	# used by the Kibana server to perform maintenance on the kibana_index at startup. Your Kibana
	# users will still need to authenticate with Elasticsearch (which is proxied through
	# the Kibana server)
	# elasticsearch.username: "user"
	# elasticsearch.password: "pass"
	# SSL for outgoing requests from the Kibana Server to the browser (PEM formatted)
	# server.ssl.cert: /path/to/your/server.crt
	# server.ssl.key: /path/to/your/server.key
	# Optional setting to validate that your Elasticsearch backend uses the same key files (PEM formatted)
	# elasticsearch.ssl.cert: /path/to/your/client.crt
	# elasticsearch.ssl.key: /path/to/your/client.key
	# If you need to provide a CA certificate for your Elasticsearch instance, put
	# the path of the pem file here.
	# elasticsearch.ssl.ca: /path/to/your/CA.pem
	# Set to false to have a complete disregard for the validity of the SSL
	# certificate.
	# elasticsearch.ssl.verify: true
	# Time in milliseconds to wait for elasticsearch to respond to pings, defaults to
	# request_timeout setting
	# elasticsearch.pingTimeout: 1500
	# Time in milliseconds to wait for responses from the back end or elasticsearch.# The Elasticsearch instance to use for all your queries.
	# elasticsearch.url: "http://localhost:9200"
	# preserve_elasticsearch_host true will send the hostname specified in 'elasticsearch'. If you set it to false,
	# then the host you use to connect to *this* Kibana instance will be sent.
	# elasticsearch.preserveHost: true
	# Kibana uses an index in Elasticsearch to store saved searches, visualizations
	# and dashboards. It will create a new index if it doesn't already exist.
	# This must be > 0
	# elasticsearch.requestTimeout: 30000
	# Time in milliseconds for Elasticsearch to wait for responses from shards.
	# Set to 0 to disable.
	# elasticsearch.shardTimeout: 0
	# Time in milliseconds to wait for Elasticsearch at Kibana startup before retrying
	# elasticsearch.startupTimeout: 5000
	# Set the path to where you would like the process id file to be created.
	# pid.file: /var/run/kibana.pid
	# If you would like to send the log output to a file you can set the path below.
	# logging.dest: stdout
	# Set this to true to suppress all logging output.
	# logging.silent: false
	# Set this to true to suppress all logging output except for error messages.
	# logging.quiet: false
	# Set this to true to log all events, including system usage information and all requests.
	# logging.verbose: false
EOF

	if [ -a "$KIBANA_CONF" ] 
	then 
		echo "....File di configurazione $KIBANA_FILE generato con successo!"
	else 
		echo "????????????????????????????????????????????????????????????????????????"
		echo "Problema nella generazione del file $KIBANA_FILE installazione fermata!"
		echo "????????????????????????????????????????????????????????????????????????"
		exit
	fi
}



CreateOpenSSLConf(){

	echo "#################################################################"
	echo "Crea configurazione OpenSSL"
	echo "#################################################################"

	if [ -a "$OPENSSL_CONF.old" ]
	then
	   echo "File $OPENSSL_CONF.old esiste"
	else
	  echo "File $OPENSSL_CONF.old non esiste"
	  if [ -a "$OPENSSL_CONF" ] 
	  then 
		cp $OPENSSL_CONF $OPENSSL_CONF.old
	  fi
	fi

cat > $OPENSSL_CONF << EOF
	#
	# OpenSSL example configuration file.
	# This is mostly being used for generation of certificate requests.
	#

	# This definition stops the following lines choking if HOME isn't
	# defined.
	HOME			= .
	RANDFILE		= $ENV::HOME/.rnd

	# Extra OBJECT IDENTIFIER info:
	#oid_file		= $ENV::HOME/.oid
	oid_section		= new_oids

	# To use this configuration file with the "-extfile" option of the
	# "openssl x509" utility, name here the section containing the
	# X.509v3 extensions to use:
	# extensions		= 
	# (Alternatively, use a configuration file that has only
	# X.509v3 extensions in its main [= default] section.)

	[ new_oids ]

	# We can add new OIDs in here for use by 'ca', 'req' and 'ts'.
	# Add a simple OID like this:
	# testoid1=1.2.3.4
	# Or use config file substitution like this:
	# testoid2=${testoid1}.5.6

	# Policies used by the TSA examples.
	tsa_policy1 = 1.2.3.4.1
	tsa_policy2 = 1.2.3.4.5.6
	tsa_policy3 = 1.2.3.4.5.7

	####################################################################
	[ ca ]
	default_ca	= CA_default		# The default ca section

	####################################################################
	[ CA_default ]

	dir		= ./demoCA		# Where everything is kept
	certs		= $dir/certs		# Where the issued certs are kept
	crl_dir		= $dir/crl		# Where the issued crl are kept
	database	= $dir/index.txt	# database index file.
	#unique_subject	= no			# Set to 'no' to allow creation of
						# several ctificates with same subject.
	new_certs_dir	= $dir/newcerts		# default place for new certs.

	certificate	= $dir/cacert.pem 	# The CA certificate
	serial		= $dir/serial 		# The current serial number
	crlnumber	= $dir/crlnumber	# the current crl number
						# must be commented out to leave a V1 CRL
	crl		= $dir/crl.pem 		# The current CRL
	private_key	= $dir/private/cakey.pem# The private key
	RANDFILE	= $dir/private/.rand	# private random number file

	x509_extensions	= usr_cert		# The extentions to add to the cert

	# Comment out the following two lines for the "traditional"
	# (and highly broken) format.
	name_opt 	= ca_default		# Subject Name options
	cert_opt 	= ca_default		# Certificate field options

	# Extension copying option: use with caution.
	# copy_extensions = copy

	# Extensions to add to a CRL. Note: Netscape communicator chokes on V2 CRLs
	# so this is commented out by default to leave a V1 CRL.
	# crlnumber must also be commented out to leave a V1 CRL.
	# crl_extensions	= crl_ext

	default_days	= 365			# how long to certify for
	default_crl_days= 30			# how long before next CRL
	default_md	= default		# use public key default MD
	preserve	= no			# keep passed DN ordering

	# A few difference way of specifying how similar the request should look
	# For type CA, the listed attributes must be the same, and the optional
	# and supplied fields are just that :-)
	policy		= policy_match

	# For the CA policy
	[ policy_match ]
	countryName		= match
	stateOrProvinceName	= match
	organizationName	= match
	organizationalUnitName	= optional
	commonName		= supplied
	emailAddress		= optional

	# For the 'anything' policy
	# At this point in time, you must list all acceptable 'object'
	# types.
	[ policy_anything ]
	countryName		= optional
	stateOrProvinceName	= optional
	localityName		= optional
	organizationName	= optional
	organizationalUnitName	= optional
	commonName		= supplied
	emailAddress		= optional

	####################################################################
	[ req ]
	default_bits		= 2048
	default_keyfile 	= privkey.pem
	distinguished_name	= req_distinguished_name
	attributes		= req_attributes
	x509_extensions	= v3_ca	# The extentions to add to the self signed cert

	# Passwords for private keys if not present they will be prompted for
	# input_password = secret
	# output_password = secret

	# This sets a mask for permitted string types. There are several options. 
	# default: PrintableString, T61String, BMPString.
	# pkix	 : PrintableString, BMPString (PKIX recommendation before 2004)
	# utf8only: only UTF8Strings (PKIX recommendation after 2004).
	# nombstr : PrintableString, T61String (no BMPStrings or UTF8Strings).
	# MASK:XXXX a literal mask value.
	# WARNING: ancient versions of Netscape crash on BMPStrings or UTF8Strings.
	string_mask = utf8only

	# req_extensions = v3_req # The extensions to add to a certificate request

	[ req_distinguished_name ]
	countryName			= Country Name (2 letter code)
	countryName_default		= AU
	countryName_min			= 2
	countryName_max			= 2

	stateOrProvinceName		= State or Province Name (full name)
	stateOrProvinceName_default	= Some-State

	localityName			= Locality Name (eg, city)

	0.organizationName		= Organization Name (eg, company)
	0.organizationName_default	= Internet Widgits Pty Ltd

	# we can do this but it is not needed normally :-)
	#1.organizationName		= Second Organization Name (eg, company)
	#1.organizationName_default	= World Wide Web Pty Ltd

	organizationalUnitName		= Organizational Unit Name (eg, section)
	#organizationalUnitName_default	=

	commonName			= Common Name (e.g. server FQDN or YOUR name)
	commonName_max			= 64

	emailAddress			= Email Address
	emailAddress_max		= 64

	# SET-ex3			= SET extension number 3

	[ req_attributes ]
	challengePassword		= A challenge password
	challengePassword_min		= 4
	challengePassword_max		= 20

	unstructuredName		= An optional company name

	[ usr_cert ]

	# These extensions are added when 'ca' signs a request.

	# This goes against PKIX guidelines but some CAs do it and some software
	# requires this to avoid interpreting an end user certificate as a CA.

	basicConstraints=CA:FALSE

	# Here are some examples of the usage of nsCertType. If it is omitted
	# the certificate can be used for anything *except* object signing.

	# This is OK for an SSL server.
	# nsCertType			= server

	# For an object signing certificate this would be used.
	# nsCertType = objsign

	# For normal client use this is typical
	# nsCertType = client, email

	# and for everything including object signing:
	# nsCertType = client, email, objsign

	# This is typical in keyUsage for a client certificate.
	# keyUsage = nonRepudiation, digitalSignature, keyEncipherment

	# This will be displayed in Netscape's comment listbox.
	nsComment			= "OpenSSL Generated Certificate"

	# PKIX recommendations harmless if included in all certificates.
	subjectKeyIdentifier=hash
	authorityKeyIdentifier=keyid,issuer

	# This stuff is for subjectAltName and issuerAltname.
	# Import the email address.
	# subjectAltName=email:copy
	# An alternative to produce certificates that aren't
	# deprecated according to PKIX.
	# subjectAltName=email:move

	# Copy subject details
	# issuerAltName=issuer:copy

	#nsCaRevocationUrl		= http://www.domain.dom/ca-crl.pem
	#nsBaseUrl
	#nsRevocationUrl
	#nsRenewalUrl
	#nsCaPolicyUrl
	#nsSslServerName

	# This is required for TSA certificates.
	# extendedKeyUsage = critical,timeStamping

	[ v3_req ]

	# Extensions to add to a certificate request

	basicConstraints = CA:FALSE
	keyUsage = nonRepudiation, digitalSignature, keyEncipherment

	[ v3_ca ]


	# Extensions for a typical CA


	# PKIX recommendation.

	subjectKeyIdentifier=hash

	authorityKeyIdentifier=keyid:always,issuer

	# This is what PKIX recommends but some broken software chokes on critical
	# extensions.
	#basicConstraints = critical,CA:true
	# So we do this instead.
	basicConstraints = CA:true

	# Key usage: this is typical for a CA certificate. However since it will
	# prevent it being used as an test self-signed certificate it is best
	# left out by default.
	# keyUsage = cRLSign, keyCertSign

	# Some might want this also
	# nsCertType = sslCA, emailCA

	# Include email address in subject alt name: another PKIX recommendation
	subjectAltName=IP:$IP_ELK
	# Copy issuer details
	# issuerAltName=issuer:copy

	# DER hex encoding of an extension: beware experts only!
	# obj=DER:02:03
	# Where 'obj' is a standard or added object
	# You can even override a supported extension:
	# basicConstraints= critical, DER:30:03:01:01:FF

	[ crl_ext ]

	# CRL extensions.
	# Only issuerAltName and authorityKeyIdentifier make any sense in a CRL.

	# issuerAltName=issuer:copy
	authorityKeyIdentifier=keyid:always

	[ proxy_cert_ext ]
	# These extensions should be added when creating a proxy certificate

	# This goes against PKIX guidelines but some CAs do it and some software
	# requires this to avoid interpreting an end user certificate as a CA.

	basicConstraints=CA:FALSE

	# Here are some examples of the usage of nsCertType. If it is omitted
	# the certificate can be used for anything *except* object signing.

	# This is OK for an SSL server.
	# nsCertType			= server

	# For an object signing certificate this would be used.
	# nsCertType = objsign

	# For normal client use this is typical
	# nsCertType = client, email

	# and for everything including object signing:
	# nsCertType = client, email, objsign

	# This is typical in keyUsage for a client certificate.
	# keyUsage = nonRepudiation, digitalSignature, keyEncipherment

	# This will be displayed in Netscape's comment listbox.
	nsComment			= "OpenSSL Generated Certificate"

	# PKIX recommendations harmless if included in all certificates.
	subjectKeyIdentifier=hash
	authorityKeyIdentifier=keyid,issuer

	# This stuff is for subjectAltName and issuerAltname.
	# Import the email address.
	# subjectAltName=email:copy
	# An alternative to produce certificates that aren't
	# deprecated according to PKIX.
	# subjectAltName=email:move

	# Copy subject details
	# issuerAltName=issuer:copy

	#nsCaRevocationUrl		= http://www.domain.dom/ca-crl.pem
	#nsBaseUrl
	#nsRevocationUrl
	#nsRenewalUrl
	#nsCaPolicyUrl
	#nsSslServerName

	# This really needs to be in place for it to be a proxy certificate.
	proxyCertInfo=critical,language:id-ppl-anyLanguage,pathlen:3,policy:foo

	####################################################################
	[ tsa ]

	default_tsa = tsa_config1	# the default TSA section

	[ tsa_config1 ]

	# These are used by the TSA reply generation only.
	dir		= ./demoCA		# TSA root directory
	serial		= $dir/tsaserial	# The current serial number (mandatory)
	crypto_device	= builtin		# OpenSSL engine to use for signing
	signer_cert	= $dir/tsacert.pem 	# The TSA signing certificate
						# (optional)
	certs		= $dir/cacert.pem	# Certificate chain to include in reply
						# (optional)
	signer_key	= $dir/private/tsakey.pem # The TSA private key (optional)

	default_policy	= tsa_policy1		# Policy if request did not specify it
						# (optional)
	other_policies	= tsa_policy2, tsa_policy3	# acceptable policies (optional)
	digests		= md5, sha1		# Acceptable message digests (mandatory)
	accuracy	= secs:1, millisecs:500, microsecs:100	# (optional)
	clock_precision_digits  = 0	# number of digits after dot. (optional)
	ordering		= yes	# Is ordering defined for timestamps?
					# (optional, default: no)
	tsa_name		= yes	# Must the TSA name be included in the reply?
					# (optional, default: no)
	ess_cert_id_chain	= no	# Must the ESS cert id chain be included?
					# (optional, default: no)
EOF

}


CreateNginixConfiguration() {

	echo "#################################################################"
	echo "Crea configurazione Elasticsearch"
	echo "#################################################################"


	if [ -a "$NGINIX_CONF.old" ]
	then
	   echo "File $NGINIX_CONF.old esiste"
	else
	  echo "File $NGINIX_CONF.old non esiste"
	  if [ -a "$NGINIX_CONF" ] 
	  then 
	  	cp $NGINIX_CONF $NGINIX_CONF.old
	  fi
	fi


cat > $NGINIX_CONF << EOF
	
server {
    listen 80;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443;
    server_name elk.log;   

   ssl_certificate           ${PKI_PATH_CERT};
   ssl_certificate_key       ${PKI_PATH_KEY};

   ssl on;
   ssl_session_cache  builtin:1000  shared:SSL:10m;
   #ssl_protocols  TLSv1 TLSv1.1 TLSv1.2;
   #ssl_ciphers HIGH:!aNULL:!eNULL:!EXPORT:!CAMELLIA:!DES:!MD5:!PSK:!RC4;
   ssl_protocols  SSLv3 TLSv1 TLSv1.1 TLSv1.2;
   ssl_ciphers    HIGH:!aNULL:!MD5;
   ssl_prefer_server_ciphers on;


   auth_basic "Restricted Access";
   auth_basic_user_file /etc/nginx/htpasswd.users;
   
   location / {
	proxy_pass http://127.0.0.1:5601/;
	proxy_http_version 1.1;
	proxy_set_header Upgrade \$http_upgrade;
	proxy_set_header Connection 'upgrade';
	proxy_set_header Host \$host;
	proxy_cache_bypass \$http_upgrade;
	}
   }
EOF
}

CreateElasticsearchConfiguration() {

	echo "#################################################################"
	echo "Crea configurazione Elasticsearch"
	echo "#################################################################"

	MEMORY_USE=`free -g | awk 'NR==2{printf "%s\n", $2/2 }'`

	if [ -a "$ELASTIC_CONF.old" ]
	then
	   echo "File $ELASTIC_CONF.old esiste"
	else
	  echo "File $ELASTIC_CONF.old non esiste"
	  if [ -a "$ELASTIC_CONF" ] 
	  then 
		cp $ELASTIC_CONF $ELASTIC_CONF.old
	  fi
	fi


cat > $ELASTIC_CONF << EOF
# ======================== Elasticsearch Configuration =========================
#
# NOTE: Elasticsearch comes with reasonable defaults for most settings.
#       Before you set out to tweak and tune the configuration, make sure you
#       understand what are you trying to accomplish and the consequences.
#
# The primary way of configuring a node is via this file. This template lists
# the most important settings you may want to configure for a production cluster.
#
# Please see the documentation for further information on configuration options:
# <http://www.elastic.co/guide/en/elasticsearch/reference/current/setup-configuration.html>
#
# ---------------------------------- Cluster -----------------------------------
#
# Use a descriptive name for your cluster:
#
# cluster.name: my-application
#
# ------------------------------------ Node ------------------------------------
#
# Use a descriptive name for the node:
#
# node.name: node-1
#
# Add custom attributes to the node:
#
# node.rack: r1
#
# ----------------------------------- Paths ------------------------------------
#
# Path to directory where to store the data (separate multiple locations by comma):
#
# path.data: /path/to/data
#
# Path to log files:
#
# path.logs: /path/to/logs
#
# ----------------------------------- Memory -----------------------------------
#
# Lock the memory on startup:
#
# bootstrap.mlockall: true
#
# Make sure that the "ES_HEAP_SIZE" environment variable is set to about half the memory
# available on the system and that the owner of the process is allowed to use this limit
ES_HEAP_SIZE : ${MEMORY_USE}G
#
# Elasticsearch performs poorly when the system is swapping the memory.
#
# ---------------------------------- Network -----------------------------------
#
# Set the bind address to a specific IP (IPv4 or IPv6):
#
network.host : localhost
#
# Set a custom port for HTTP:
#
# http.port: 9200
#
# For more information, see the documentation at:
# <http://www.elastic.co/guide/en/elasticsearch/reference/current/modules-network.html>
#
# --------------------------------- Discovery ----------------------------------
#
# Pass an initial list of hosts to perform discovery when new node is started:
# The default list of hosts is ["127.0.0.1", "[::1]"]
#
# discovery.zen.ping.unicast.hosts: ["host1", "host2"]
#
# Prevent the "split brain" by configuring the majority of nodes (total number of nodes / 2 + 1):
#
# discovery.zen.minimum_master_nodes: 3
#
# For more information, see the documentation at:
# <http://www.elastic.co/guide/en/elasticsearch/reference/current/modules-discovery.html>
#
# ---------------------------------- Gateway -----------------------------------
#
# Block initial recovery after a full cluster restart until N nodes are started:
#
# gateway.recover_after_nodes: 3
#
# For more information, see the documentation at:
# <http://www.elastic.co/guide/en/elasticsearch/reference/current/modules-gateway.html>
#
# ---------------------------------- Various -----------------------------------
#
# Disable starting multiple nodes on a single system:
#
# node.max_local_storage_nodes: 1
#
# Require explicit names when deleting indices:
#
# action.destructive_requires_name: true
EOF

}


CreateLogstashInputConfiguration(){

	echo "#################################################################"
	echo "Crea configurazione Logstash {input}"
	echo "#################################################################"


	if [ -a "$LOGSTASH_CONF.old" ]
	then
	   echo "File $LOGSTASH_CONF.old esiste"
	else
	  echo "File $LOGSTASH_CONF.old non esiste"
	  if [ -a "$LOGSTASH_CONF" ] 
	  then 
		cp $LOGSTASH_CONF $LOGSTASH_CONF.old
	  fi
	fi

cat > $LOGSTASH_CONF << EOF
input {
  tcp {
    port => 5000
    type => omfwd
  }
  udp {
    port => 5000
    type => omfwd
    workers => 30
    queue_size => 4000
  }
}
EOF


}

CreateLogstashFilterConfiguration() {
	
	echo "#################################################################"
	echo "Crea configurazione Logstash {filter}"
	echo "#################################################################"

	if [ -a "$LOGSTASH_SYSLOG.old" ]
	then
	   echo "File $LOGSTASH_SYSLOG.old esiste"
	else
	  echo "File $LOGSTASH_SYSLOG.old non esiste"
	  if [ -a "$LOGSTASH_SYSLOG" ] 
	  then 
		cp $LOGSTASH_SYSLOG $LOGSTASH_SYSLOG.old
	  fi
	fi


cat > $LOGSTASH_SYSLOG << EOF
	filter {
	  if [type] == "omfwd" {
	    grok {
	      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
	      add_field => [ "received_at", "%{@timestamp}" ]
	      add_field => [ "received_from", "%{host}" ]
	    }
	    syslog_pri { }
	    date {
	      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
	    }
	  }
	}
EOF
}

CreateLogstashOutputConfiguration() {

	echo "#################################################################"
	echo "Crea configurazione Logstash {output}"
	echo "#################################################################"
	if [ -a "$LOGSTASH_ELASTICSEARCH.old" ]
	then
	   echo "File $LOGSTASH_ELASTICSEARCH.old esiste"
	else
	  echo "File $LOGSTASH_ELASTICSEARCH.old non esiste"
	  if [ -a "$LOGSTASH_ELASTICSEARCH" ] 
	  then 
		cp $LOGSTASH_ELASTICSEARCH $LOGSTASH_ELASTICSEARCH.old
	  fi
	fi


cat > $LOGSTASH_ELASTICSEARCH << EOF
	output {
	  elasticsearch {
	    hosts => ["localhost:9200"]
	    #index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
	    #document_type => "%{[@metadata][type]}"
	  }
	}
EOF
}


CreateLogstashAllConfiguration() {

	echo "#################################################################"
	echo "Crea configurazione Logstash {output}"
	echo "#################################################################"
	if [ -a "$LOGSTASH_ELASTICSEARCH_ALL.old" ]
	then
	   echo "File $LOGSTASH_ELASTICSEARCH_ALL.old esiste"
	else
	  echo "File $LOGSTASH_ELASTICSEARCH_ALL.old non esiste"
	  if [ -a "$LOGSTASH_ELASTICSEARCH_ALL" ] 
	  then 
		cp $LOGSTASH_ELASTICSEARCH_ALL $LOGSTASH_ELASTICSEARCH_ALL.old
	  fi
	fi


cat > $LOGSTASH_CONF << EOF
	input {
	  tcp {
	    port => 5000
	    type => omfwd
	  }
	  udp {
	    port => 5000
	    type => omfwd
	    workers => 30
	    queue_size => 4000
	  }
	}	
	filter {
	  if [type] == "omfwd" {
	    grok {
	      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
	      add_field => [ "received_at", "%{@timestamp}" ]
	      add_field => [ "received_from", "%{host}" ]
	    }
	    syslog_pri { }
	    date {
	      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
	    }
	  }
	}
	output {
	  elasticsearch {
	    hosts => ["localhost:9200"]
	    #index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
	    #document_type => "%{[@metadata][type]}"
	  }
	}
EOF
}


CreateSSLCertificate() {
	echo "#################################################################"
	echo "Creo directori Certificati"
	echo "#################################################################"
	mkdir -p  /etc/pki/tls/certs
	mkdir /etc/pki/tls/private
	echo "#################################################################"
	echo "Creo Certificati"
	echo "#################################################################"  
	openssl req -config ${OPENSSL_CONF} -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout ${PKI_PATH_KEY} -out ${PKI_PATH_CERT}
}

ServiceElasticsearchStart() {
	echo "#################################################################"
	echo "Avvia servizio Elsticsearch"
	echo "#################################################################"
	update-rc.d elasticsearch defaults 
	update-rc.d elasticsearch enable	
	service elasticsearch start
}

ServiceLogstashStart() {
	echo "#################################################################"
	echo "Avvia servizio Logstash"
	echo "#################################################################"
	update-rc.d logstash defaults 
	update-rc.d logstash enable	
	service logstash configtest	
	service logstash restart	
	
}

ServiceKibanaStart() {
	echo "#################################################################"
	echo "Avvia servizio Kibana"
	echo "#################################################################"
	update-rc.d kibana defaults	
	update-rc.d kibana enable
	service kibana start
}

ServiceNginxStart() {
	echo "#################################################################"
	echo "Avvia servizio Nginx"
	echo "#################################################################"
	update-rc.d nginx defaults
	update-rc.d nginx enable
	service nginx start
}


SetUpElasticSearch()
{
	echo "#################################################################"
	echo "Istallo certificati repositori elasticsearch"
	echo "#################################################################"
	wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add - 
	echo "deb https://packages.elastic.co/elasticsearch/${ELASTIC_VERSION}/debian stable main" | sudo tee -a /etc/apt/sources.list.d/elasticsearch-${ELASTIC_VERSION}.list
	echo "#################################################################"
	echo "Aggiorno sistema e installo ElasticSearch"
	echo "#################################################################"
	sudo apt-get update && sudo apt-get install elasticsearch
	

}

SetPipCurator()
{
	echo "#################################################################"
	echo "Verifico Aggiornamenti di sistema!"
	echo "#################################################################"
	apt-get update
	echo "#################################################################"
	echo "Aggiorno sistema!"
	echo "#################################################################"
	apt-get upgrade
	echo "#################################################################"
	echo "Installo pip"
	echo "#################################################################"
	sudo apt-get install python-pip
	echo "#################################################################"
	echo "Installo Curator"
	echo "#################################################################"
	pip install elasticsearch-curator
	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	echo "Esempio per curator !"
	echo " curator delete indices --older-than 14 --time-unit days --timestring %Y.%m.%d --regex '^logstash-'"
	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"		
}

SetUpJava()
{
	echo "#################################################################"
	echo "Verifico Aggiornamenti di sistema!"
	echo "#################################################################"
	apt-get update
	echo "#################################################################"
	echo "Aggiorno sistema!"
	echo "#################################################################"
	apt-get upgrade
	echo "#################################################################"
	echo "Installo JDK"
	echo "#################################################################"
	echo "	- Aggiungo repositori Oracle"
	sudo add-apt-repository ppa:webupd${JDK_Ver}team/java
	sudo apt-get update
	echo "#################################################################"
	echo "	- Installo JDK"
	echo "#################################################################"
	sudo apt-get install oracle-java${JDK_Ver}-installer
}



SetupKibana() {
	echo "#################################################################"
	echo "Installo certificati repositori Kibana"
	echo "#################################################################"
	wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
	echo "#################################################################"
	echo "Aggiunge repositori Kibana"
	echo "#################################################################"
	echo "deb http://packages.elastic.co/kibana/${KIBANA_VER}/debian stable main" | sudo tee -a /etc/apt/sources.list.d/kibana-${KIBANA_VER}.x.list
	echo "#################################################################"
	echo "Installo Kibana"
	echo "#################################################################"
	apt-get update && apt-get -y install kibana
}

SetUpNginix()
{
	echo "#################################################################"
	echo "Installo certificati repositori Kibana"
	echo "#################################################################"
	sudo apt-get install nginx apache2-utils
	sudo htpasswd -c /etc/nginx/htpasswd.users $KIBANA_ADMIN_USER
	
}
SetUpLogstash()
{
	echo "#################################################################"
	echo "Installo certificati repositori Logstash"
	echo "#################################################################"

	echo "deb http://packages.elastic.co/logstash/${LOGSTASH_VERSION}/debian stable main" | sudo tee -a /etc/apt/sources.list.d/logstash-.x.list
	echo "#################################################################"
	echo "Aggiorno sistema e installo Logstash"
	echo "#################################################################"
	sudo apt-get update && sudo apt-get install logstash

}

setupKibanaDasboard(){
	
	echo "#################################################################"
	echo "Creo Dashboard Kibana"
	echo "#################################################################"
	
curl -L -O https://download.elastic.co/beats/dashboards/beats-dashboards-1.1.0.zip
apt-get -y install unzip
unzip beats-dashboards-*.zip
cd beats-dashboards-*
./load.sh


}
choiceKibanaDashBoard()
{
	setupKibanaDasboard
}

choiceJava() {
	#
	# Avvio Setup di Java
	#
	SetUpJava
}

choiceElasticSearch() {
	#
	# Avvio Setup di Elastic
	#
	SetUpElasticSearch
	CreateElasticsearchConfiguration
	ServiceElasticsearchStart
}

choiceKibana() {
	#
	# Avvio Setup di Kibana
	#
	SetupKibana
	CreateKibanaConfiguration
	ServiceKibanaStart
}

choiceNginx() {
	#
	# Avvio Setup di Nginx
	#
	SetUpNginix
	CreateNginixConfiguration
	ServiceNginxStart
}

choiceLogstash() {
	#
	# Avvio Setup di Logstash
	#
	SetUpLogstash
        CreateSSLCertificate
	CreateLogstashAllConfiguration
	ServiceLogstashStart
}
fullInst(){
	choiceJava
	choiceElasticSearch
	choiceKibana
	choiceNginx
	choiceLogstash
	choiceKibanaDashBoard
	SetPipCurator
	
}

# ----------------------------------
# Step #2: User defined function
# ----------------------------------
pause(){
  read -p "Press [Enter] key to continue..." fackEnterKey
}

one(){
	echo "one() called"
        pause
}
 
# do something in two()
two(){
	echo "two() called"
        pause
}
 


# function to display menus
show_option_menus() {
	clear
	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"	
	echo " Installazione Server ELK su ubuntu"
	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	echo "a. Crea Certificati "
	echo "b. Crea configurazione SSL"
	echo "c. Crea file configurazione Nginx"
	echo "d. Crea file configurazione ElasticSearch"
	echo "e. Crea file configurazione Kibana"
	echo "f. Crea file configurazione Logstash"
	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	echo "x. Torna a Menu principale"
	read_options_menu
}

# function to display menus
show_main_menus() {
	clear
	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"	
	echo " Installazione Server ELK su ubuntu"
	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	echo "1. Installazione Completa"
	echo "2. Install Java"
	echo "3. Install ElasticSearch"
	echo "4. Install Kibana"
	echo "5. Install Nginx"
	echo "6. Install Logstash"
	echo "7. Setup Kibana Dashboard"
	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	echo "8. Opzioni Avanzate"
	echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	echo "9. Exit"

}

read_options_menu(){
	local choice
	read -p "Enter choice [ a - h] " choice
	case $choice in
		a) CreateSSLCertificate ;;
		b) CreateOpenSSLConf ;;
		c) CreateNginixConfiguration ;;
		d) CreateElasticsearchConfiguration ;;
		e) CreateKibanaConfiguration;;
		f) CreateLogstashAllConfiguration;;
		x) main ;;	
		*) echo -e "${RED}Error...${STD}" && sleep 2
	esac
}


read_main_menu(){
	local choice
	read -p "Enter choice [ 1 - 7] " choice
	case $choice in
		1) fullInst ;;
		2) choiceJava ;;
		3) choiceElasticSearch ;;
		4) choiceKibana ;;
		5) choiceNginx ;;
		6) choiceLogstash ;;
		7) choiceKibanaDashBoard ;;	
		8) show_option_menus ;;			
		9) exit 0;;
		*) echo -e "${RED}Error...${STD}" && sleep 2
	esac
}

main()
{
	# ----------------------------------------------
	# Step #3: Trap CTRL+C, CTRL+Z and quit singles
	# ----------------------------------------------
	trap '' SIGINT SIGQUIT SIGTSTP
	 
	# -----------------------------------
	# Step #4: Main logic - infinite loop
	# ------------------------------------
	#while true
	#do
	 
		show_main_menus
		read_main_menu
	#done
}

main





