import dataset

def store_cert(certificado,key,serialNumber,subject):
    db = dataset.connect('sqlite:///database.db')
    table = db['cert']
    table.insert({
        'cert': certificado,
        'key': key,
        'serialNumber': serialNumber,
        'subject': subject
    })

def list_cert():
    db = dataset.connect('sqlite:///database.db')
    table = db['cert']
    return table.all()
