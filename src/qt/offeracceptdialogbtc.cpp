#include "offeracceptdialogbtc.h"
#include "ui_offeracceptdialogbtc.h"
#include "init.h"
#include "util.h"
#include "offerpaydialog.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "platformstyle.h"
#include "syscoingui.h"
#include <QMessageBox>
#include "rpcserver.h"
#include "pubkey.h"
#include "wallet/wallet.h"
#include "main.h"
#include "utilmoneystr.h"
#include <QDesktopServices>
#if QT_VERSION < 0x050000
#include <QUrl>
#else
#include <QUrlQuery>
#endif
#include <QPixmap>
#if defined(HAVE_CONFIG_H)
#include "config/syscoin-config.h" /* for USE_QRCODE */
#endif
#include <QDebug>
#ifdef USE_QRCODE
#include <qrencode.h>
#endif
using namespace std;
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
extern const CRPCTable tableRPC;
OfferAcceptDialogBTC::OfferAcceptDialogBTC(const PlatformStyle *platformStyle, QString alias, QString offer, QString quantity, QString notes, QString title, QString currencyCode, QString qstrPrice, QString sellerAlias, QString address, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::OfferAcceptDialogBTC), platformStyle(platformStyle), alias(alias), offer(offer), notes(notes), quantity(quantity), title(title), sellerAlias(sellerAlias), address(address)
{
    ui->setupUi(this);
	QString theme = GUIUtil::getThemeName();  
	ui->aboutShadeBTC->setPixmap(QPixmap(":/images/" + theme + "/about_btc"));
	double dblPrice = qstrPrice.toDouble()*quantity.toUInt();
	string strfPrice = strprintf("%f", dblPrice);
	QString fprice = QString::fromStdString(strfPrice);
	string strCurrencyCode = currencyCode.toStdString();
	ui->escrowDisclaimer->setText(tr("<font color='blue'>Please note escrow is not available since you are paying in BTC, only SYS payments can be escrowed. </font>"));
	ui->bitcoinInstructionLabel->setText(tr("After paying for this item, please enter the Bitcoin Transaction ID and click on the confirm button below. You may use the QR Code to the left to scan the payment request into your wallet or click on the Open BTC Wallet if you are on the desktop and have Bitcoin Core installed."));
	ui->acceptMessage->setText(tr("Are you sure you want to purchase %1 of '%2' from merchant: '%3'? To complete your purchase please pay %4 BTC to %5 using your Bitcoin wallet.").arg(quantity).arg(title).arg(sellerAlias).arg(fprice).arg(address));
	string strPrice = strprintf("%f", dblPrice);
	price = QString::fromStdString(strPrice);

	if (!platformStyle->getImagesOnButtons())
	{
		ui->confirmButton->setIcon(QIcon());
		ui->openBtcWalletButton->setIcon(QIcon());
		ui->cancelButton->setIcon(QIcon());

	}
	else
	{
		ui->confirmButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/transaction_confirmed"));
		ui->openBtcWalletButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/send"));
		ui->cancelButton->setIcon(platformStyle->SingleColorIcon(":/icons/" + theme + "/quit"));
	}	
	this->offerPaid = false;
	connect(ui->confirmButton, SIGNAL(clicked()), this, SLOT(tryAcceptOffer()));
	connect(ui->openBtcWalletButton, SIGNAL(clicked()), this, SLOT(openBTCWallet()));

#ifdef USE_QRCODE
	QString message = "Payment for offer ID " + this->offer + " on Syscoin Decentralized Marketplace";
	SendCoinsRecipient info;
	info.address = this->address;
	info.label = this->sellerAlias;
	info.message = message;
	ParseMoney(price.toStdString(), info.amount);
	QString uri = GUIUtil::formatBitcoinURI(info);

	ui->lblQRCode->setText("");
    if(!uri.isEmpty())
    {
        // limit URI length
        if (uri.length() > MAX_URI_LENGTH)
        {
            ui->lblQRCode->setText(tr("Resulting URI too long, try to reduce the text for label / message."));
        } else {
            QRcode *code = QRcode_encodeString(uri.toUtf8().constData(), 0, QR_ECLEVEL_L, QR_MODE_8, 1);
            if (!code)
            {
                ui->lblQRCode->setText(tr("Error encoding URI into QR Code."));
                return;
            }
            QImage myImage = QImage(code->width + 8, code->width + 8, QImage::Format_RGB32);
            myImage.fill(0xffffff);
            unsigned char *p = code->data;
            for (int y = 0; y < code->width; y++)
            {
                for (int x = 0; x < code->width; x++)
                {
                    myImage.setPixel(x + 4, y + 4, ((*p & 1) ? 0x0 : 0xffffff));
                    p++;
                }
            }
            QRcode_free(code);
            ui->lblQRCode->setPixmap(QPixmap::fromImage(myImage).scaled(128, 128));
        }
    }
#endif
}
void OfferAcceptDialogBTC::on_cancelButton_clicked()
{
    reject();
}
OfferAcceptDialogBTC::~OfferAcceptDialogBTC()
{
    delete ui;
}


bool OfferAcceptDialogBTC::CheckUnconfirmedPaymentInBTC(const QString &strBTCTxId, const QString& myprice)
{
	m_strBTCTxId = strBTCTxId; 
	CAmount priceAmount = 0;
	if(!ParseMoney(myprice.toStdString(), priceAmount))
	{
        QMessageBox::critical(this, windowTitle(),
            tr("Error parsing price: ") + myprice,
                QMessageBox::Ok, QMessageBox::Ok);
		return;
	}
	QNetworkAccessManager *nam = new QNetworkAccessManager(this);
	connect(nam,SIGNAL(sslErrors(QNetworkReply*,QList<QSslError>)),this,SLOT(onIgnoreSSLErrors(QNetworkReply*,QList<QSslError>)));  
	connect(nam, SIGNAL(finished(QNetworkReply *)), this, SLOT(slotUnconfirmedFinished(QNetworkReply *)));
	QUrl url("https://blockchain.info/unconfirmed-transactions?format=json");
	QNetworkRequest request(url);
	nam->get(request);
}
void OfferAcceptDialogBTC::onIgnoreSSLErrors(QNetworkReply *reply, QList<QSslError> error)  
{  
   reply->ignoreSslErrors(error);  
}  
void OfferAcceptDialogBTC::slotUnconfirmedFinished(QNetworkReply * reply){
	if(reply->error() != QNetworkReply::NoError) {
		qDebug() << "Error making request: ";
		qDebug() << reply->errorString();
		return;
	}
	CAmount valueAmount = 0;
	bool doubleSpend = false;
	

	QByteArray bytes = reply->readAll();
	QString str = QString::fromUtf8(bytes.data(), bytes.size());
	UniValue outerValue;
	bool read = outerValue.read(str.toStdString());
	if (read)
	{
		UniValue outerObj = outerValue.get_obj();
		UniValue txsValue = find_value(outerObj, "txs");
		if (txsValue.isArray())
		{
			UniValue txs = txsValue.get_array();
			for (unsigned int txidx = 0; txidx < txs.size(); txidx++) {
				const UniValue& tx = txs[txidx];	
				UniValue hashValue = find_value(tx, "hash");
				if (hashValue.isStr())
				{
					if(m_strBTCTxId.toStdString() !=  hashValue.get_str())
						continue;
				}
				else
					continue;
				UniValue doubleSpendValue = find_value(tx, "double_spend");
				if (doubleSpendValue.isBool())
				{
					doubleSpend = doubleSpendValue.get_bool();
					if(doubleSpend)
					{
						QMessageBox::critical(this, windowTitle(),
							tr("Payment cannot be completed. Outputs seem to be double spent!"),
								QMessageBox::Ok, QMessageBox::Ok);
						return;
					}
				}
				UniValue outputsValue = find_value(tx, "out");
				if (outputsValue.isArray())
				{
					UniValue outputs = outputsValue.get_array();
					for (unsigned int idx = 0; idx < outputs.size(); idx++) {
						const UniValue& output = outputs[idx];	
						UniValue addressValue = find_value(output, "addr");
						if(addressValue.isStr())
						{
							if(addressValue.get_str() == address.toStdString())
							{
								UniValue paymentValue = find_value(output, "value");
								if(paymentValue.isNum())
								{
									valueAmount += paymentValue.get_int64();
									if(valueAmount >= priceAmount)
									{
										QMessageBox::information(this, windowTitle(),
											tr("Payment found in the Bitcoin blockchain!"),
												QMessageBox::Ok, QMessageBox::Ok);
										return;
									}
								}
							}
								
						}
					}
				}
			}
		}	
	}
	else
	{
		QMessageBox::critical(this, windowTitle(),
			tr("Cannot parse JSON response: ") + str,
				QMessageBox::Ok, QMessageBox::Ok);
		return;
	}	
	reply->deleteLater();
	QMessageBox::warning(this, windowTitle(),
		tr("Payment not found in the Bitcoin blockchain! Please try again later."),
			QMessageBox::Ok, QMessageBox::Ok);	
}
void OfferAcceptDialogBTC::slotConfirmedFinished(QNetworkReply * reply){
	if(reply->error() != QNetworkReply::NoError) {
        QMessageBox::critical(this, windowTitle(),
            tr("Error making request: ") + reply->errorString(),
                QMessageBox::Ok, QMessageBox::Ok);
		return;
	}
	CAmount valueAmount = 0;
	bool doubleSpend = false;
	qDebug() << "Reply: ";
	qDebug() << QVariant(reply->error()).toString();
	long time;
	int height;
		
	QByteArray bytes = reply->readAll();
	QString str = QString::fromUtf8(bytes.data(), bytes.size());
	int statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
	qDebug() << "Status Code: ";
	qDebug() << QVariant(statusCode).toString();
	UniValue outerValue;
	bool read = outerValue.read(str.toStdString());
	if (read)
	{
		qDebug() << "Read";
		UniValue outerObj = outerValue.get_obj();
		UniValue heightValue = find_value(outerObj, "block_height");
		if (heightValue.isNum())
			height = heightValue.get_int();
		UniValue timeValue = find_value(outerObj, "time");
		if (timeValue.isNum())
			time = timeValue.get_int64();
		UniValue doubleSpendValue = find_value(outerObj, "double_spend");
		if (doubleSpendValue.isBool())
		{
			doubleSpend = doubleSpendValue.get_bool();
			if(doubleSpend)
			{
				QMessageBox::critical(this, windowTitle(),
					tr("Payment cannot be completed. Outputs seem to be double spent!"),
						QMessageBox::Ok, QMessageBox::Ok);
				return;
			}
		}
		UniValue outputsValue = find_value(outerObj, "out");
		if (outputsValue.isArray())
		{
			qDebug() << "Outputs";
			UniValue outputs = outputsValue.get_array();
			for (unsigned int idx = 0; idx < outputs.size(); idx++) {
				const UniValue& output = outputs[idx];	
				UniValue addressValue = find_value(output, "addr");
				if(addressValue.isStr())
				{
					if(addressValue.get_str() == address.toStdString())
					{
						qDebug() << "Address match";
						UniValue paymentValue = find_value(output, "value");
						if(paymentValue.isNum())
						{
							valueAmount += paymentValue.get_int64();
							qDebug() << "Check value";
							if(valueAmount >= priceAmount)
							{
								qDebug() << "Found";
								QDateTime timestamp;
								timestamp.setTime_t(time);
								QMessageBox::information(this, windowTitle(),
									tr("Transaction ID %1 was found in the Bitcoin blockchain! Full payment has been detected in block %2 at %3. It is recommended that you confirm payment by opening your Bitcoin wallet and seeing the funds in your account.").arg(m_strBTCTxId).arg(height).arg(timestamp.toString(Qt::SystemLocaleShortDate)),
									QMessageBox::Ok, QMessageBox::Ok);
								return;
							}
						}
					}
						
				}
			}
		}
	}
	else
	{
		QMessageBox::critical(this, windowTitle(),
			tr("Cannot parse JSON response: ") + str,
				QMessageBox::Ok, QMessageBox::Ok);
		return;
	}
	
	reply->deleteLater();
	QMessageBox::warning(this, windowTitle(),
		tr("Payment not found in the Bitcoin blockchain! Please try again later."),
			QMessageBox::Ok, QMessageBox::Ok);	
}
bool OfferAcceptDialogBTC::CheckPaymentInBTC(const QString &strBTCTxId, const QString& myprice)
{
	m_strBTCTxId = strBTCTxId; 
	CAmount priceAmount = 0;
	if(!ParseMoney(myprice.toStdString(), priceAmount))
	{
        QMessageBox::critical(this, windowTitle(),
            tr("Error parsing price: ") + myprice,
                QMessageBox::Ok, QMessageBox::Ok);
		return;
	}
	QNetworkAccessManager *nam = new QNetworkAccessManager(this);
	connect(nam,SIGNAL(sslErrors(QNetworkReply*,QList<QSslError>)),this,SLOT(onIgnoreSSLErrors(QNetworkReply*,QList<QSslError>)));  
	connect(name, SIGNAL(finished(QNetworkReply *)), this, SLOT(slotConfirmedFinished(QNetworkReply *)));
	QUrl url("https://blockchain.info/tx/" + strBTCTxId + "?format=json");
	QNetworkRequest request(url);
	nam->get(request);
	return false;


}

bool OfferAcceptDialogBTC::lookup(const QString &lookupid, QString& myprice)
{
	string strError;
	string strMethod = string("offerinfo");
	UniValue params(UniValue::VARR);
	UniValue result;
	params.push_back(lookupid.toStdString());

    try {
        result = tableRPC.execute(strMethod, params);

		if (result.type() == UniValue::VOBJ)
		{
			const UniValue &offerObj = result.get_obj();

			const string &strPrice = find_value(offerObj, "price").get_str();
			myprice = QString::fromStdString(strPrice);
			return true;
		}
	}
	catch (UniValue& objError)
	{
		QMessageBox::critical(this, windowTitle(),
			tr("Could not find this offer, please check the offer ID and that it has been confirmed by the blockchain: ") + lookupid,
				QMessageBox::Ok, QMessageBox::Ok);
		return true;

	}
	catch(std::exception& e)
	{
		QMessageBox::critical(this, windowTitle(),
			tr("There was an exception trying to locate this offer, please check the offer ID and that it has been confirmed by the blockchain: ") + QString::fromStdString(e.what()),
				QMessageBox::Ok, QMessageBox::Ok);
		return true;
	}
	return false;


}
// send offeraccept with offer guid/qty as params and then send offerpay with wtxid (first param of response) as param, using RPC commands.
void OfferAcceptDialogBTC::tryAcceptOffer()
{
		QString myprice;
		if (ui->btctxidEdit->text().trimmed().isEmpty()) {
            ui->btctxidEdit->setText("");
            QMessageBox::critical(this, windowTitle(),
            tr("Please enter a valid Bitcoin Transaction ID into the input box and try again"),
                QMessageBox::Ok, QMessageBox::Ok);
            return;
        }
		if(!lookup(this->offer, myprice))
		{
            QMessageBox::critical(this, windowTitle(),
            tr("Could not find this offer, please check the offer ID and that it has been confirmed by the blockchain: ") + this->offer,
                QMessageBox::Ok, QMessageBox::Ok);
            return;
		}

		if(!CheckPaymentInBTC(ui->btctxidEdit->text().trimmed(), myprice) && !CheckUnconfirmedPaymentInBTC(ui->btctxidEdit->text().trimmed(), myprice))
			return;
		
		acceptOffer();

}
void OfferAcceptDialogBTC::acceptOffer(){
		UniValue params(UniValue::VARR);
		UniValue valError;
		UniValue valResult;
		UniValue valId;
		UniValue result ;
		string strReply;
		string strError;

		string strMethod = string("offeraccept");
		if(this->quantity.toLong() <= 0)
		{
			QMessageBox::critical(this, windowTitle(),
				tr("Invalid quantity when trying to accept offer!"),
				QMessageBox::Ok, QMessageBox::Ok);
			return;
		}
		this->offerPaid = false;
		params.push_back(this->alias.toStdString());
		params.push_back(this->offer.toStdString());
		params.push_back(this->quantity.toStdString());
		params.push_back(this->notes.toStdString());
		params.push_back(ui->btctxidEdit->text().toStdString());

	    try {
            result = tableRPC.execute(strMethod, params);
			if (result.type() != UniValue::VNULL)
			{
				const UniValue &arr = result.get_array();
				string strResult = arr[0].get_str();
				QString offerAcceptTXID = QString::fromStdString(strResult);
				if(offerAcceptTXID != QString(""))
				{
					OfferPayDialog dlg(platformStyle, this->title, this->quantity, this->price, "BTC", this);
					dlg.exec();
					this->offerPaid = true;
					OfferAcceptDialogBTC::accept();
					return;

				}
			}
		}
		catch (UniValue& objError)
		{
			strError = find_value(objError, "message").get_str();
			QMessageBox::critical(this, windowTitle(),
			tr("Error accepting offer: \"%1\"").arg(QString::fromStdString(strError)),
				QMessageBox::Ok, QMessageBox::Ok);
			return;
		}
		catch(std::exception& e)
		{
			QMessageBox::critical(this, windowTitle(),
				tr("General exception when accepting offer"),
				QMessageBox::Ok, QMessageBox::Ok);
			return;
		}
}
void OfferAcceptDialogBTC::openBTCWallet()
{
	QString message = "Payment for offer ID " + this->offer + " on Syscoin Decentralized Marketplace";
	SendCoinsRecipient info;
	info.address = this->address;
	info.label = this->sellerAlias;
	info.message = message;
	ParseMoney(price.toStdString(), info.amount);
	QString uri = GUIUtil::formatBitcoinURI(info);
	QDesktopServices::openUrl(QUrl(uri, QUrl::TolerantMode));
}
bool OfferAcceptDialogBTC::getPaymentStatus()
{
	return this->offerPaid;
}
