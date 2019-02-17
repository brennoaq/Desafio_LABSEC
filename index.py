import os,random, db
from werkzeug.utils import secure_filename
from flask import Flask, flash, request, redirect, url_for, send_from_directory,send_file
from src.file_hashing.file_hash import FileHashing
from src.pair_generator.key_pair import KeyPairGenerator
from OpenSSL import crypto, SSL
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime


app = Flask(__name__)
UPLOAD_FOLDER = './static'
ALLOWED_EXTENSIONS = set(['txt'])
ALLOWED_EXTENSIONS = set(['png'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route("/")
def index():
    return ''' 
    <!DOCTYPE html>
<html>
	<head>

		<title>Test LABSEC</title>
		<meta charset="utf-8">
	
         <style>
            body{
	                background: #0d2b72da url('imagens/background.png');
	                font: 16px "Arial", helvetica, Sans-serif;
                }

                #principal{
                    width: 900px;
                }

                #menu{
                    background: #0d2b72da;
                    padding: 18px
                }

                #conteudo{
                    background: #1b46acda;
                    padding: 10px;
                }

                #rodape{
                        text-align: center;
                }


                a{
                    color: #000000;
                    text-decoration: none;
                    font-weight: bold;
                    padding: 5px;
                }

                h1{
                    color:#828271;
                    font-size: 1.2em;
                }

                h2{
                    color:#828271;
                    font-size: 1.2em;	
                }

                .img-campanha{
                    border: 10px solid #c3c3ae;
                }

                .italico{
                    font-style: italic;
                }

                .negrito{
                    font-weight: bold;
                }
        </style>
	</head>
	<body>
        <table border="0" width="900" align="center">
            <div id="principal">
                
                <img src="./labsec-brenno/imagens/capa.png">
                
                <div id="menu">
                    <a href="/">HOME</a> |
                    <a href="/file">RESUMO CRIPTOGRÁFICO</a> |
                    <a href="/keys">GERAR CHAVES ASSIMETRÍCAS</a> |
                    <a href="/DigitalCertificate">GERAR CERTIFICADOS DIGITAIS</a> |
                    <a href="/listSerialNumber">REPOSITÓRIO PARA CERTIFICADOS EMITIDOS</a>
                </div>
                    
                <div id="conteudo"><!-- inicio do conteudo-->

                    <h1>Contato</h1>

                    <p class="italico">
                        "Não há liberdade sem privacidade."
                    </p>

                    <div>
                        <strong>E-mail:</strong> brennoaraujoqueiroz@gmail.com 
                        <br>
                        <strong>GitHub:</strong> <a href="https://github.com/brennoaq">https://github.com/brennoaq</a>
                    </div>
                    
                    
                </div><!-- fim do conteudo-->

                <div id="rodape">
                    <h4>Todos os direitos reservados</h4>
                </div>

            </div>
		</table>

	</body>
</html>
    '''


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/file", methods=['GET', 'POST'])
def file():
    if request.method == 'POST':
        if request.method == 'POST':
            # check if the post request has the file part
            if 'file' not in request.files:
                flash('No file part')
                return redirect(url_for('index'))

            file = request.files['file']
            # if user does not select file, browser also
            # submit an empty part without filename
            if file.filename == '':
                flash('No selected file')
                return redirect(url_for('index'))

            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                return redirect(url_for('uploaded_file', file=filename))
                

    return '''
        <!doctype html>
        <title>Upload new File</title>
        <h1>Upload new File</h1>
        <form method=post enctype=multipart/form-data>
        <input type=file name=file>
        <input type=submit value=Upload>
        </form>
    '''


@app.route('/hash/<file>')
def uploaded_file(file):
    with app.open_resource('static/' + file) as f:
        return FileHashing().hash_file(f.read())


@app.route("/keys")
def keysAssimetric():
    a = KeyPairGenerator()

    key1 = a.priv
    result = ''
    for line in key1.splitlines():
        result += line.decode() + '\n'

    key2 = a.pub
    result2 = ''
    for line in key2.splitlines():
        result2 += line.decode() + '\n'

    return '''
        
        <!doctype html>
        <title>Chaves  publicas e privadas </title>
        <br/>
        <h1>Chave publica </h1>'''+result2+'''

        <br/>
        <h1>Chave privada </h1>'''+result


@app.route("/DigitalCertificate")
def create_self_signed_cert():
    ca_key = crypto.PKey()


    ca_key.generate_key(crypto.TYPE_RSA, 2048)

    ca_cert = crypto.X509()
    ca_cert.set_version(2)
    serial_number = random.randint(50000000, 100000000)
    ca_cert.set_serial_number(serial_number)
    ca_subj = ca_cert.get_subject()
    ca_subj.commonName = "My CA"
    subject_name = ca_subj.commonName


    ca_cert.add_extensions([
        crypto.X509Extension("subjectKeyIdentifier".encode('utf-8'), False,
                            "hash".encode('utf-8'), subject=ca_cert),
    ])

    ca_cert.add_extensions([
        crypto.X509Extension("authorityKeyIdentifier".encode('utf-8'), False,
                            "keyid:always".encode('utf-8'), issuer=ca_cert),
    ])

    ca_cert.add_extensions([
    
        crypto.X509Extension("basicConstraints".encode('utf-8'), False, "CA:TRUE".encode('utf-8')),
        crypto.X509Extension("keyUsage".encode('utf-8'), False, "keyCertSign, cRLSign".encode('utf-8')),
    ])

    ca_cert.set_issuer(ca_subj)
    ca_cert.set_pubkey(ca_key)

    ca_cert.gmtime_adj_notBefore(0)
    ca_cert.gmtime_adj_notAfter(10*365*24*60*60)
    ca_cert.sign(ca_key, 'sha256')

    # Save certificate
    with open("ca.crt", "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))

    # Save private key
    with open("ca.key", "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key))

    cert_ca = crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert).decode('utf-8')
    key_ca = crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key).decode('utf-8')     

    db.store_cert(cert_ca, key_ca, serial_number, subject_name)

    ###############
    # Client Cert #
    ###############

    client_key = crypto.PKey()
    client_key.generate_key(crypto.TYPE_RSA, 2048)
    client_cert = crypto.X509()
    client_cert.set_version(2)
    serial_number2 = random.randint(50000000, 100000000)
    client_cert.set_serial_number(random.randint(50000000, 100000000))
   
    client_subj = client_cert.get_subject()
    client_subj.commonName = "Client"
    subject_name2 = client_subj.commonName

    client_cert.add_extensions([
        crypto.X509Extension("basicConstraints".encode('utf-8'), False, "CA:FALSE".encode('utf-8')),
        crypto.X509Extension("subjectKeyIdentifier".encode('utf-8'), False,
                            "hash".encode('utf-8'), subject=client_cert),
    ])

    client_cert.add_extensions([
        crypto.X509Extension("authorityKeyIdentifier".encode('utf-8'), False,
                            "keyid:always".encode('utf-8'), issuer=ca_cert),
        crypto.X509Extension("extendedKeyUsage".encode('utf-8'), False, "clientAuth".encode('utf-8')),
        crypto.X509Extension("keyUsage".encode('utf-8'), False, "digitalSignature".encode('utf-8')),
    ])

    client_cert.set_issuer(ca_subj)
    client_cert.set_pubkey(client_key)
    client_cert.gmtime_adj_notBefore(0)
    client_cert.gmtime_adj_notAfter(10*365*24*60*60)
    client_cert.sign(ca_key, 'sha256')


    cert = crypto.dump_certificate(crypto.FILETYPE_PEM, client_cert).decode('utf-8')
    key = crypto.dump_privatekey(crypto.FILETYPE_PEM, client_key).decode('utf-8')     

    # db.store_cert(cert, key, serial_number, subject_name)

    return  ''' 
        <!doctype html>
        <title> Certificado </title>
        <br/>
        <br/>
        <h1>  </h1> '''+ cert_ca

@app.route('/listSerialNumber')
def list_serialNumber():
    serials = db.list_cert()
   
    html = [
         '''
        <!doctype html>
        <title> Certificado </title>
        '''
    ]


    for serial in serials:
        html.append(
            '''
            <h3>Serial Number {}</h3>
            '''.format(serial['id'])
        )
        
        html.append(
            '''
            <h3>{}</h3>
            '''.format(serial['serialNumber'])
        )

        html.append(
            '''
            <h3>{}</h3>
            '''.format(serial['subject'])
        )


    return '\n'.join(html)    

@app.route('/listCertificate')
def list_certificate():
    certs = db.list_cert()

    html = [
        '''
        <!doctype html>
        <title> Certificado </title>
        '''
    ]

    for cert in certs: 
        html.append( 
            '''
            <h3>Certificate {}</h3>
            '''.format(cert['id'])
        )

        html.append(
            ''' 
            <h5>{}</h5>

            '''.format(cert['cert'])
        )

    return '\n'.join(html)
