/****************************************************************************
** Copyright (c) 2014 Debao Zhang <hello@debao.me>
** All right reserved.
**
** Permission is hereby granted, free of charge, to any person obtaining
** a copy of this software and associated documentation files (the
** "Software"), to deal in the Software without restriction, including
** without limitation the rights to use, copy, modify, merge, publish,
** distribute, sublicense, and/or sell copies of the Software, and to
** permit persons to whom the Software is furnished to do so, subject to
** the following conditions:
**
** The above copyright notice and this permission notice shall be
** included in all copies or substantial portions of the Software.
**
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
** EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
** MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
** NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
** LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
** OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
** WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
**
****************************************************************************/
#ifndef FTPSERVER_H
#define FTPSERVER_H

#include <QTcpServer>
class QTextCodec;
class QSslConfiguration;

class FtpPI;
class FtpServerPrivate;
class FtpServer : public QTcpServer
{
    Q_OBJECT
public:
    enum Permission {
        Read = 0x01,
        Write = 0x02,
        Exec = 0x04
    };
    Q_DECLARE_FLAGS(Permissions, Permission)

    explicit FtpServer(QObject *parent=0);
    explicit FtpServer(const QString &rootPath, QObject *parent = 0);
    ~FtpServer();

    QString rootPath() const;
    QTextCodec *codec() const;
    QString welcomeMessage() const;

public slots:
    void setRootPath(const QString &rootPath);
    void setCodec(const char *codecName);
    void setWelcomeMessage(const QString &message);
    void addAccount(const QString &user, const QString &passWord=QString(), const QString &home=QString(), Permissions permissions = Read);
#ifndef QT_NO_SSL
    void setSslConfiguration(const QSslConfiguration &configuration);
#endif

protected:
    void incomingConnection(qintptr socketDescriptor);

private:
    Q_DECLARE_PRIVATE(FtpServer)
    Q_DISABLE_COPY(FtpServer)
    friend class FtpPI;
    FtpServerPrivate * const d_ptr;
};

Q_DECLARE_OPERATORS_FOR_FLAGS(FtpServer::Permissions)

#endif // FTPSERVER_H
