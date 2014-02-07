#include "ftpserver.h"

#include <QCoreApplication>
#include <QHostAddress>
#include <QSslKey>
#include <QSslConfiguration>
#include <QDebug>
#include <QDir>

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    FtpServer server;

    server.setWelcomeMessage("Hi,\nWelcome to debao's Ftp server.");
    server.addAccount("anonymous");  //Enable anonymous user with ReadOnly access.

    server.addAccount("hello",  //User Name
                      "qt",     //PassWord
                      "/Users/debao",       //Directory
                      FtpServer::Read | FtpServer::Write | FtpServer::Exec);

    QSslConfiguration configuration;
    QFile privateKey(":/ca/ca-key.pem");
    privateKey.open(QFile::ReadOnly);
    configuration.setPrivateKey(QSslKey(privateKey.readAll(), QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey));
    QFile certificate(":/ca/ca-cert.pem");
    certificate.open(QFile::ReadOnly);
    configuration.setLocalCertificate(QSslCertificate(certificate.readAll()));
    server.setSslConfiguration(configuration);

    if (server.listen(QHostAddress::LocalHost, 2121)) {
        qDebug()<<"Listening at port 2121";
    } else {
        qDebug()<<"Failed.";
        return -1;
    }

    return app.exec();
}
