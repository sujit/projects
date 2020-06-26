from flask import Flask, render_template, request
import dataset
import sqlalchemy

'''

Initial DB properties:
    * Create Table:
        CREATE TABLE `mapplogs` (
            `cve_id`	TEXT DEFAULT 'False' UNIQUE,
            `date`	TEXT DEFAULT 'False',
            `month`	TEXT DEFAULT 'False',
            `vendor`	TEXT DEFAULT 'False',
            `author`	TEXT DEFAULT 'False',
            `source`	TEXT DEFAULT 'False',
            `exploit_url`	TEXT DEFAULT 'False',
            `sigable`	TEXT DEFAULT 'False',
            `rules`	TEXT DEFAULT 'False',
            `reason`	TEXT DEFAULT 'False',
            PRIMARY KEY(`cve_id`)
        );

    * Create Index:
        CREATE INDEX `idx_` ON `mapplogs` (
            `cve_id`	ASC
        );

'''

app = Flask(__name__)
app.config["SECRET_KEY"] = "A secret key you won't forget"


@app.route('/hello')
def index():
    return 'Hello World!'


@app.route('/')
def mappform():
    return render_template('layout.html')


@app.route('/pass', methods=['POST'])
def mappmetafeed():
    # form = FlaskForm(request.form)

    formSave = False
    if request.method == "POST":
        snortrules = request.form.getlist('snortsids')
        mapp_month = request.form.getlist('mapp_month')
        nmCVEID = request.form.getlist('nmCVEID')
        nmDate = request.form.getlist('nmDate')
        nmAuthor = request.form.getlist('nmAuthor')
        nmReasons = request.form.getlist('nmReasons')
        nmSigable = request.form.getlist('nmSigable')
        nmSource = request.form.getlist('nmSource')
        nmITWExploitURL = request.form.getlist('nmITWExploitURL')
        nmVendor = request.form.getlist('nmVendor')

        # Connect DB and perform the CRUD operation
        dbObj = dataset.connect('sqlite:///db//mapp.db')
        dbTable = dbObj['mapplogs']

        # Perform the required validations before the metadata submission
        if 'ITW' in nmSource and nmSigable[0] == 'Yes':
            nmSource = "ITW"
            try:
                dbTable.insert(
                    dict(
                        cve_id=nmCVEID[0],
                        date=nmDate[0],
                        month=mapp_month[0],
                        vendor=nmVendor[0],
                        author=nmAuthor[0],
                        source=nmSource,
                        exploit_url=nmITWExploitURL[0],
                        sigable=nmSigable[0],
                        rules=snortrules[0]
                    ))
                formSave = True
            except sqlalchemy.exc.IntegrityError:
                print(sqlalchemy.exc.IntegrityError)
        if 'ITW' in nmSource and nmSigable[0] == 'No':
            nmSource = "ITW"
            try:
                dbTable.insert(
                    dict(
                        cve_id=nmCVEID[0],
                        date=nmDate[0],
                        month=mapp_month[0],
                        vendor=nmVendor[0],
                        author=nmAuthor[0],
                        source=nmSource,
                        exploit_url=nmITWExploitURL[0],
                        sigable=nmSigable[0],
                        reason=nmReasons[0]
                    ))
                formSave = True
            except sqlalchemy.exc.IntegrityError:
                print(sqlalchemy.exc.IntegrityError)
        elif 'MAPP' in nmSource and nmSigable[0] == 'Yes':
            nmSource = "MAPP"
            try:
                dbTable.insert(
                    dict(
                        cve_id=nmCVEID[0],
                        date=nmDate[0],
                        month=mapp_month[0],
                        vendor=nmVendor[0],
                        author=nmAuthor[0],
                        source=nmSource,
                        sigable=nmSigable[0],
                        rules=snortrules[0]
                    ))
                formSave = True
            except sqlalchemy.exc.IntegrityError:
                print(sqlalchemy.exc.IntegrityError)
        elif 'MAPP' in nmSource and nmSigable[0] == 'No':
            nmSource = "MAPP"
            try:
                dbTable.insert(
                    dict(
                        cve_id=nmCVEID[0],
                        date=nmDate[0],
                        month=mapp_month[0],
                        vendor=nmVendor[0],
                        author=nmAuthor[0],
                        source=nmSource,
                        sigable=nmSigable[0],
                        reason=nmReasons[0]
                    ))
                formSave = True
            except sqlalchemy.exc.IntegrityError:
                print(sqlalchemy.exc.IntegrityError)
        elif 'No info' in nmSource:
            nmSource = "No info"
            try:
                dbTable.insert(
                    dict(
                        cve_id=nmCVEID[0],
                        date=nmDate[0],
                        month=mapp_month[0],
                        vendor=nmVendor[0],
                        author=nmAuthor[0],
                        source=nmSource
                    ))
                formSave = True
            except sqlalchemy.exc.IntegrityError:
                print(sqlalchemy.exc.IntegrityError)

    if formSave is True:
        return '<h1> Document saved. </h1> <hr>'
    else:
        return'<h1> Exception occured during submit!</h1> <hr>'


if __name__ == '__main__':
    app.run(debug=True, port=8080, host='0.0.0.0')

