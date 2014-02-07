#include "ftpserver.h"

#include <QCoreApplication>
#include <QHostAddress>
#include <QDebug>
#include <QDir>

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    FtpServer server;
    server.setWelcomeMessage("Hi,\nWelcome to debao's Ftp server.");
    server.addAccount("anonymous"); //Enable anonymous user with ReadOnly access.

    server.addAccount("hello",  //User Name
                      "qt",     //PassWord
                      "/Users/debao",       //Directory
                      FtpServer::Read | FtpServer::Write | FtpServer::Exec);

    if (server.listen(QHostAddress::LocalHost, 2121)) {
        qDebug()<<"Listening at port 2121";
    } else {
        qDebug()<<"Failed.";
        return -1;
    }

    return app.exec();
}
