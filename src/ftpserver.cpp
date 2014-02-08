/****************************************************************************
** Copyright (c) 2013-2014 Debao Zhang <hello@debao.me>
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
#include "ftpserver.h"

#include <QTimer>
#include <QTime>
#include <QDir>
#include <QTextCodec>
#include <QDateTime>
#include <QDebug>
#include <QList>
#include <QHostAddress>
#include <QTcpServer>
#ifndef QT_NO_SSL
#include <QSslSocket>
#include <QSslConfiguration>
#else
#include <QTcpSocket>
#endif
#include <QLocale>
#include <QMap>

class FtpPI;
class FtpDTP;
class FtpDtpData;

#define DEBUG_DTP

/**********************************************************************
 *
 * Ftp Account Data
 *
 *********************************************************************/
class FtpAccountData
{
public:
    FtpAccountData();
    FtpAccountData(const QString &passWord, const QString &homeDir, FtpServer::Permissions permissions);
    QString passWord;
    QString homePath;
    FtpServer::Permissions permissions;
};

/**********************************************************************
 *
 * FtpServerPrivate class
 *
 *********************************************************************/
class FtpServerPrivate
{
    Q_DECLARE_PUBLIC(FtpServer)
public:
    FtpServerPrivate(FtpServer *q, const QString &rootPath);

    FtpServer *q_ptr;
    QString rootPath;
    QTextCodec *codec;
#ifndef QT_NO_SSL
    QSslConfiguration sslConfiguration;
#endif
    QString welcome;
    QMap<QString, FtpAccountData> accounts;
};

/**********************************************************************
 *
 * Ftp Command Data
 *
 *********************************************************************/
class FtpDtpData
{
public:
    enum Direction
    {
        None,
        Read,
        Write
    };

    FtpDtpData();
    FtpDtpData(const QByteArray &data);
    FtpDtpData(QIODevice *device, Direction dir);
    ~FtpDtpData();

    QByteArray data;
    QIODevice *device;
    Direction rw;
};

/**********************************************************************
 *
 * Protocol Interpreter
 *
 *********************************************************************/
class FtpPI : public QObject
{
    Q_OBJECT
public:
    FtpPI(int socketDescriptor, FtpServer *parent=0);
    ~FtpPI();

    QHostAddress peerAddress() const;
    quint16 peerPort() const;
    void close();

    void sendResponse(int responseCode, const QString &responseText);

signals:
    void finished();

private slots:
    void onReadyRead();
    void onError(QAbstractSocket::SocketError);
    void onDtpStateChanged(int);

    void processFtpCommand();

    //vvvvvvvvvvvv RFC959 vvvvvvvvvvvvvvv
    void doUSER(const QString &userName);
    void doPASS(const QString &password);
    void doACCT(const QString &accountInfo);
    void doCWD(const QString &path);
    void doCDUP(const QString &);
    //void doSMNT(const QString &path);
    void doQUIT(const QString &);
    //void doREIN(const QString &);
    void doPORT(const QString &param);
    void doPASV(const QString &);
    void doTYPE(const QString &typeCode);
    void doSTRU(const QString &structureCode);
    //void doMODE(const QString &modeCode);
    void doRETR(const QString &path);
    void doSTOR(const QString &path);
    //void doSTOU(const QString &);
    //void doAPPE(const QString &path);
    void doALLO(const QString &param);
    //void doREST(const QString &marker); //See RFC3659
    void doRNFR(const QString &path);
    void doRNTO(const QString &path);
    void doABOR(const QString &);
    void doDELE(const QString &path);
    void doRMD(const QString &path);
    void doMKD(const QString &path);
    void doPWD(const QString &);
    void doLIST(const QString &path);
    void doNLST(const QString &path);
    //void doSITE(const QString &param);
    void doSYST(const QString &);
    //void doSTAT(const QString &path);
    //void doHELP(const QString &param);
    void doNOOP(const QString &);
    //^^^^^^^^^^^^ RFC959 ^^^^^^^^^^^^^^^

    //vvvvvvvvvvvv RFC2228 vvvvvvvvvvvvvvv
#ifndef QT_NO_SSL
    void doAUTH(const QString &param);
    //void doADAT(const QString &);
    void doPROT(const QString &param);
    void doPBSZ(const QString &param);
    //void doCCC(const QString &);
    //void doMIC(const QString &);
    //void doCONF(const QString &);
    //void doENC(const QString &);
#endif
    //^^^^^^^^^^^^ RFC2228 ^^^^^^^^^^^^^^^

    //vvvvvvvvvvvv RFC2389 vvvvvvvvvvvvvvv
    void doFEAT(const QString &);
    void doOPTS(const QString &param);
    //^^^^^^^^^^^^ RFC2389 ^^^^^^^^^^^^^^^

    //vvvvvvvvvvvv RFC2428 vvvvvvvvvvvvvvv
    //void doEPRT(const QString &);
    //void doEPSV(const QString &);
    //^^^^^^^^^^^^ RFC2428 ^^^^^^^^^^^^^^^

    //vvvvvvvvvvvv RFC2640 vvvvvvvvvvvvvvv
    //void doLANG(const QString &);
    //^^^^^^^^^^^^ RFC2640 ^^^^^^^^^^^^^^^

    //vvvvvvvvvvvv RFC3659 vvvvvvvvvvvvvvv
    //void doMDTM(const QString &path);
    void doSIZE(const QString &path);
    void doREST(const QString &marker); //See also RFC959
    //void doTVFS(const QString &path);
    //void doMLST(const QString &);
    //void doMLSD(const QString &);
    //^^^^^^^^^^^^ RFC3659 ^^^^^^^^^^^^^^^

    //vvvvvvvvvvvv RFC775 vvvvvvvvvvvvvvv
    void doXCUP(const QString &);
    void doXMKD(const QString &path);
    void doXPWD(const QString &);
    void doXRMD(const QString &path);
    //^^^^^^^^^^^^ RFC775 ^^^^^^^^^^^^^^^

private:
    void sendDtpData(const QByteArray &bytes);
    void sendDtpData(const QString &data);
    void sendDtpData(QIODevice *device);
    void recvDtpData(QIODevice *device);
    bool vertifyAuthenticated();
    bool vertifyPermission(int permission);
    bool vertifyClientPathExist(const QString &clientPath, QFileInfo &info);
    bool vertifyParamsNotEmpty(const QString &params);

    QString cleanClientPath(const QString &path) const;
    QString generateLISTLine(const QFileInfo &entry) const;

    FtpServer *m_server;
#ifndef QT_NO_SSL
    QSslSocket *m_socket;
#else
    QTcpSocket *m_socket;
#endif
    QString m_currentDir;
    QString m_homeDir;
    FtpDTP *m_dtp;

    bool m_authenticated;
    QString m_accountName;
    FtpAccountData m_account;

    bool m_waitForDtpToConnect;
    bool m_waitForDtpToClose;
    bool m_waitForQuit;

    QStringList m_pendingCmds;
    QString m_currentCmd;
    QString m_lastCmd;
    QString m_filePath; //Used by rename
};

/**********************************************************************
 *
 * Data Transfer Process
 *
 *********************************************************************/
class FtpDTP : public QObject
{
    Q_OBJECT
public:
    enum ConnectState {
        CS_ClientFound,
        CS_Connected,
        CS_Closed,
        CS_ClientNotFound,
        CS_ConnectionRefused
    };

    enum ConnectionType {
        CT_Active,
        CT_Passive
    };

    FtpDTP(FtpPI *parent=0);
    ~FtpDTP();

    ConnectionType connectionType() const;
    void setClientAddress(const QHostAddress &host, quint16 port);
    int setupListener(const QHostAddress &address);
    void startConnection();//connect to the client, or wait for the client connection.
    void abortConnection();
    QTcpSocket::SocketState state() const;

    void setCommandData(const FtpDtpData &data);
    void writeData();
    void readData();

    void cleanUp();

signals:
    void stateChanged(int cs);

private slots:
    void onSocketConnected();
    void onSocketReadyRead();
    void onSocketError(QAbstractSocket::SocketError);
    void onSocketConnectionClosed();
    void onSocketBytesWritten(qint64);
    void onNewSocketConnection();
    void onTimeout();

private:
    void connectToClient();
    void waitForConnection();

    QTcpServer *m_listener;
    QTcpSocket *m_dataSocket;
    ConnectionType m_connectionType;
    QHostAddress m_clientAddr;
    quint16 m_clientPort;
    FtpPI *m_ftpPI;
    QTimer *m_timer;

    FtpDtpData m_data;
};

/**********************************************************************
 *
 * FtpAccountData implemenatation
 *
 *********************************************************************/

FtpAccountData::FtpAccountData()
    :permissions(FtpServer::Read)
{

}

FtpAccountData::FtpAccountData(const QString &passWord, const QString &homeDir, FtpServer::Permissions permissions)
    :passWord(passWord), homePath(homeDir), permissions(permissions)
{

}

/**********************************************************************
 *
 * FtpDdpData implemenatation
 *
 *********************************************************************/
FtpDtpData::FtpDtpData()
    : device(0), rw(None)
{

}

FtpDtpData::FtpDtpData(const QByteArray &data)
    : data(data), device(0), rw(Write)
{

}

FtpDtpData::FtpDtpData(QIODevice *device, Direction dir)
    : device(device), rw(dir)
{

}

FtpDtpData::~FtpDtpData()
{
}

/**********************************************************************
 *
 * FtpServerPrivate implemenatation
 *
 *********************************************************************/
FtpServerPrivate::FtpServerPrivate(FtpServer *q, const QString &rootPath) :
    q_ptr(q)
{
    if (QDir(rootPath).exists())
        this->rootPath = QDir(rootPath).absolutePath();
    else
        this->rootPath = QDir::currentPath();

    codec = QTextCodec::codecForName("UTF-8");
    welcome = QLatin1String("Welcome.");
}

/**********************************************************************
 *
 * FtpPI implemenatation
 *
 *********************************************************************/
FtpPI::FtpPI(int socketDescriptor, FtpServer *parent) :
    QObject(parent), m_server(parent)
{
#ifndef QT_NO_SSL
    m_socket = new QSslSocket(this);
#else
    m_socket = new QTcpSocket(this);
#endif
    m_socket->setSocketDescriptor(socketDescriptor);
    m_currentDir = QLatin1String("/");
    m_dtp = new FtpDTP(this);
    m_authenticated = false;

    m_waitForDtpToConnect = false;
    m_waitForDtpToClose = false;
    m_waitForQuit = false;

    connect(m_socket, SIGNAL(disconnected()), this, SIGNAL(finished()));
    connect(m_socket, SIGNAL(readyRead()), this, SLOT(onReadyRead()));
    connect(m_socket, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(onError(QAbstractSocket::SocketError)));
    connect(m_dtp, SIGNAL(stateChanged(int)), this, SLOT(onDtpStateChanged(int)));

    sendResponse(200, m_server->welcomeMessage());
}

FtpPI::~FtpPI()
{

}

QHostAddress FtpPI::peerAddress() const
{
    return m_socket->peerAddress();
}

quint16 FtpPI::peerPort() const
{
    return m_socket->peerPort();
}

void FtpPI::onReadyRead()
{
    while (m_socket->canReadLine()) {
        const QByteArray line = m_socket->readLine().trimmed();
        m_pendingCmds.append(m_server->codec()->toUnicode(line));
    }

    if (!m_pendingCmds.isEmpty())
        QTimer::singleShot(0, this, SLOT(processFtpCommand()));
}

void FtpPI::onError(QAbstractSocket::SocketError /*e*/)
{

}

void FtpPI::onDtpStateChanged(int s)
{
    switch (s) {
    case FtpDTP::CS_Connected:
        if (m_waitForDtpToConnect)
            m_waitForDtpToConnect = false;
        break;
    case FtpDTP::CS_Closed:
        sendResponse(226, "OK");
        m_dtp->cleanUp();
        if (m_waitForQuit)
            m_socket->close();
        break;
    case FtpDTP::CS_ClientNotFound:
    case FtpDTP::CS_ConnectionRefused:
        if (m_waitForDtpToConnect) {
            sendResponse(425, "Can't open data connection");
            m_waitForDtpToConnect = false;
        }
        break;
    default:
        break;
    }
}

void FtpPI::sendResponse(int responseCode, const QString &responseText)
{
    QByteArray code = QByteArray::number(responseCode);
    if (!responseText.contains(QLatin1Char('\n'))) {
        // One line only
        m_socket->write(code);
        m_socket->write(" ");
        m_socket->write(m_server->codec()->fromUnicode(responseText));
        m_socket->write("\r\n");
    } else {
        // multi lines
        QStringList lines = responseText.split(QLatin1Char('\n'), QString::SkipEmptyParts);

        for (int i=0; i<lines.size(); ++i) {
            QString line = lines[i].trimmed();
            if (i == 0) {
                m_socket->write(code);
                m_socket->write("-");
            } else if (i == lines.size() - 1) {
                m_socket->write(code);
                m_socket->write(" ");
            } else {
                //1. mid-lines that starts with \d{3} should be prepended some space.
                //2. FEAT features should be prepended one space
                m_socket->write(" ");
            }
            m_socket->write(m_server->codec()->fromUnicode(line));
            m_socket->write("\r\n");
        }
    }
    m_socket->flush();

    qDebug()<<"Send: "<<responseCode<<responseText;
}

void FtpPI::sendDtpData(const QByteArray &bytes)
{
    sendResponse(150, "About to open data connection.");
    m_dtp->setCommandData(FtpDtpData(bytes));
    m_dtp->startConnection();
    if (m_dtp->state() == QAbstractSocket::ConnectedState)
        m_dtp->writeData();
    else
        m_waitForDtpToConnect = true;
}

void FtpPI::sendDtpData(const QString &data)
{
    sendDtpData(m_server->codec()->fromUnicode(data));
}

void FtpPI::sendDtpData(QIODevice *device)
{
    sendResponse(150, "About to open data connection.");
    m_dtp->setCommandData(FtpDtpData(device, FtpDtpData::Write));
    m_dtp->startConnection();
    if (m_dtp->state() == QAbstractSocket::ConnectedState)
        m_dtp->writeData();
    else
        m_waitForDtpToConnect = true;
}

void FtpPI::recvDtpData(QIODevice *device)
{
    sendResponse(150, "About to open data connection.");
    m_dtp->setCommandData(FtpDtpData(device, FtpDtpData::Read));
    m_dtp->startConnection();
    if (m_dtp->state() == QAbstractSocket::ConnectedState)
        m_dtp->readData();
    else
        m_waitForDtpToConnect = true;
}

void FtpPI::processFtpCommand()
{
    if (m_pendingCmds.isEmpty())
        return;

    if (m_waitForQuit)
        sendResponse(421, "Closing control connection.");

    QString line = m_pendingCmds.takeFirst();
    QString cmd;
    QString param;

    int idx = line.indexOf(QLatin1Char(' '));
    if (idx == 3 || idx == 4) {
        cmd = line.left(idx).toUpper();
        param = line.mid(idx + 1).trimmed();
    } else {
        cmd = line.trimmed().toUpper();
        if (cmd.size() > 4 || cmd.size() < 3) {
            sendResponse(500, "Command unrecongnized.");
            return;
        }
    }

    m_lastCmd = m_currentCmd;
    m_currentCmd = cmd;
    qDebug()<<"Recieved: "<<cmd<<param;

    bool ret = metaObject()->invokeMethod(this, QString(QLatin1String("do")+cmd).toLatin1().data(), Q_ARG(QString, param));
    if (!ret)
        sendResponse(500, "Command not support.");

    if (!m_pendingCmds.isEmpty())
        QTimer::singleShot(0, this, SLOT(processFtpCommand()));
}

QString FtpPI::cleanClientPath(const QString &path) const
{
    if (path.isEmpty())
        return m_currentDir;

    QString temp = path.startsWith(QLatin1Char('/')) ? path : m_currentDir + path;
    temp = QDir::cleanPath(temp);
    return temp;
}

QString FtpPI::generateLISTLine(const QFileInfo &entry) const
{
    // For unix ftpd, more or less like this
    //
    // drwxr-xr-x 4 abc def 2048 Nov 11 2014 a.txt
    //
    // For windows ftpd
    //
    // 01-16-02  11:14AM       <DIR>          epsgroup
    // 06-05-03  03:19PM                 1973 readme.txt

    QString line;

#ifdef Q_OS_WIN
    // Last modified, we must use english locale here.
    line += QLocale(QLocale::English).toString(entry.lastModified(), QLatin1String("MM-dd-yy  hh:mmAP"));
    if (entry.isDir())
        line += QLatin1String("       <DIR>         ");
    else
        line += QString("%1").arg(entry.size(), 20);
#else
    // Type
    if (entry.isSymLink())
        line += QLatin1Char('l');
    else if (entry.isDir())
        line += QLatin1Char('d');
    else
        line += QLatin1Char('-');

    // Permissions
    QFile::Permissions p = entry.permissions();
    line += (p & QFile::ReadOwner) ? QLatin1Char('r') : QLatin1Char('-');
    line += (p & QFile::WriteOwner) ? QLatin1Char('w') : QLatin1Char('-');
    line += (p & QFile::ExeOwner) ? QLatin1Char('x') : QLatin1Char('-');
    line += (p & QFile::ReadGroup) ? QLatin1Char('r') : QLatin1Char('-');
    line += (p & QFile::WriteGroup) ? QLatin1Char('w') : QLatin1Char('-');
    line += (p & QFile::ExeGroup) ? QLatin1Char('x') : QLatin1Char('-');
    line += (p & QFile::ReadOther) ? QLatin1Char('r') : QLatin1Char('-');
    line += (p & QFile::WriteOther) ? QLatin1Char('w') : QLatin1Char('-');
    line += (p & QFile::ExeOther) ? QLatin1Char('x') : QLatin1Char('-');

    // Links ?
    line += QLatin1String("  1");

    // Owner/group
    line += QLatin1Char(' ');
    line += entry.owner().isEmpty() ? QLatin1String("unknown") : entry.owner();
    line += QLatin1Char(' ');
    line += entry.group().isEmpty() ? QLatin1String("unknown") : entry.group();

    // File size
    line += QString::fromLatin1(" %1 ").arg(entry.size());

    // Last modified, we must use english locale here.
    //out += entry.lastModified().toString("MMM dd hh:mm");
    line += QLocale(QLocale::English).toString(entry.lastModified(), QLatin1String("MMM dd hh:mm"));
#endif

    // File name
    line += QLatin1Char(' ');
    line += entry.fileName();

    line += QLatin1String("\r\n");
    return line;
}

bool FtpPI::vertifyAuthenticated()
{
    if (!m_authenticated) {
        sendResponse(530, "Not logged in.");
        return false;
    }

    return true;
}

bool FtpPI::vertifyPermission(int permission)
{
    if ((static_cast<int>(m_account.permissions) & permission) != permission) {
        sendResponse(550, "Requested action not taken");
        return false;
    }

    return true;
}

bool FtpPI::vertifyClientPathExist(const QString &clientPath, QFileInfo &info)
{
    QString temp = cleanClientPath(clientPath);
    if (temp.startsWith(QLatin1String("/.."))) {
        sendResponse(550, "Path not valid.");
        return false;
    }

    QString realPath = m_homeDir + temp;
    info.setFile(realPath);
    if (!info.exists()) {
        sendResponse(550, "Path not found.");
        return false;
    }
    return true;
}

bool FtpPI::vertifyParamsNotEmpty(const QString &params)
{
    if (params.isEmpty()) {
        sendResponse(501, "Parameter needed");
        return false;
    }
    return true;
}

void FtpPI::doUSER(const QString &userName)
{
    // User name
    m_accountName = userName;
    QStringList users = m_server->d_func()->accounts.keys();
    if (users.contains(userName)) {
        m_account = m_server->d_func()->accounts[userName];
        sendResponse(331, "OK.");
    } else if (users.contains(QString())) {
        m_account = m_server->d_func()->accounts[QString()];
        sendResponse(331, "OK.");
    } else {
        sendResponse(530, "Invalid user name.");
    }
}

void FtpPI::doPASS(const QString &password)
{
    // Password
    if (m_lastCmd != QLatin1String("USER")) {
        sendResponse(503, "Bad sequence of commands.");
        return;
    }

    if (password == m_account.passWord || m_account.passWord.isEmpty()) {
        sendResponse(230, "OK.");
        m_authenticated = true;
        if (QDir::isAbsolutePath(m_account.homePath))
            m_homeDir = m_account.homePath;
        else
            m_homeDir = QDir::cleanPath(m_server->rootPath() + QLatin1Char('/') + m_account.homePath);
        qDebug()<<"root"<<m_homeDir;
    } else {
        sendResponse(530, "Invalid pass word.");
    }
}

void FtpPI::doACCT(const QString &accountInfo)
{
    // Account
    Q_UNUSED(accountInfo)
    if (m_lastCmd != QLatin1String("PASS")) {
        sendResponse(503, "Bad sequence of commands.");
        return;
    }

    sendResponse(200, "OK.");
}

void FtpPI::doQUIT(const QString &)
{
    // Log out
    sendResponse(221, "Goodbye.");
    if (m_dtp->state() == QAbstractSocket::ConnectedState) {
        // Wait for the Dtp finish
        m_waitForDtpToClose = true;
        m_waitForQuit = true;
    } else {
        // No files is transfered, so close the control channel.
        m_socket->close();
    }
}

void FtpPI::doRMD(const QString &path)
{
    if (!vertifyAuthenticated())
        return;
    if (!vertifyPermission(FtpServer::Exec))
        return;
    if (!vertifyParamsNotEmpty(path))
        return;
    QFileInfo info;
    if (!vertifyClientPathExist(path, info))
        return;

    if (QDir().rmdir(info.filePath()))
        sendResponse(250, "OK.");
    else
        sendResponse(550, "Error.");
}

void FtpPI::doMKD(const QString &path)
{
    if (!vertifyAuthenticated())
        return;
    if (!vertifyPermission(FtpServer::Exec))
        return;
    if (!vertifyParamsNotEmpty(path))
        return;

    QString cleanedPath = cleanClientPath(path);
    if (cleanedPath.startsWith(QLatin1String("/.."))) {
        sendResponse(550, "Path not valid.");
        return;
    }
    QString realPath = m_homeDir + cleanedPath;

    if (QDir().mkdir(realPath))
        sendResponse(257, QString("\"%1\"").arg(cleanedPath));
    else
        sendResponse(550, "Error");
}

void FtpPI::doPWD(const QString &)
{
    // Print Working Directory
//    if (!vertifyAuthenticated())
//        return;
    sendResponse(257, QString("\"%1\"").arg(m_currentDir));
}

void FtpPI::doCWD(const QString &path)
{
    if (!vertifyAuthenticated())
        return;
    if (path.isEmpty()) {
        sendResponse(501, "Parameter needed");
        return;
    }

    QString temp = cleanClientPath(path);

    if (temp.startsWith(QLatin1String("/.."))) {
        //Wrong path
        sendResponse(550, "Invalid path");
    } else {
        m_currentDir = temp.endsWith(QLatin1Char('/')) ? temp : temp + QLatin1Char('/');
        sendResponse(250, "OK");
    }
}

void FtpPI::doSYST(const QString &)
{
    // System
#ifdef Q_OS_WIN
    sendResponse(215, "Windows");
#else
    sendResponse(215, "UNIX");
#endif
}

void FtpPI::doTYPE(const QString &typeCode)
{
    // Representation Type
    if (!vertifyAuthenticated())
        return;
    Q_UNUSED(typeCode)
    sendResponse(200, "OK");
}

void FtpPI::doSTRU(const QString &structureCode)
{
    // File Structure
    if (!vertifyAuthenticated())
        return;
    Q_UNUSED(structureCode)
    sendResponse(200, "OK");
}

void FtpPI::doPASV(const QString &)
{
    // Passive mode
    if (!vertifyAuthenticated())
        return;
    quint16 port = m_dtp->setupListener(m_server->serverAddress());
    QString addr = m_server->serverAddress().toString();
    addr.replace(QLatin1Char('.'), QLatin1Char(','));

    sendResponse(227, QString::fromLatin1("Entering Passive Mode (%1,%2,%3).")
                 .arg(addr).arg(port/256).arg(port%256));
}

void FtpPI::doCDUP(const QString &)
{
    // Change to parent directory
    if (!vertifyAuthenticated())
        return;
    QDir path(m_currentDir);
    if (path.cdUp()) {
        m_currentDir = path.absolutePath();
        if (!m_currentDir.endsWith(QLatin1Char('/')))
            m_currentDir.append(QLatin1Char('/'));
        sendResponse(250, "CWD command successful.");
    } else {
        sendResponse(550, "Could not change to parent");
    }
}

void FtpPI::doLIST(const QString &path)
{
    //  List a directory
    if (!vertifyAuthenticated())
        return;
    QFileInfo info;
    if (!vertifyClientPathExist(path, info))
        return;

    if (info.isDir()) {
        QFileInfoList entryList = info.dir().entryInfoList();
        QStringList outLines;
        foreach (QFileInfo entry, entryList)
            outLines.append(generateLISTLine(entry));

        sendDtpData(outLines.join(QString()));
    } else {
        //Just one file.
        sendDtpData(generateLISTLine(info));
    }
}

void FtpPI::doNLST(const QString &path)
{
    // Name list
    if (!vertifyAuthenticated())
        return;
    QFileInfo info;
    if (!vertifyClientPathExist(path, info))
        return;

    if (info.isDir()) {
        QFileInfoList entryList = info.dir().entryInfoList();
        QStringList outLines;
        foreach (QFileInfo entry, entryList)
            outLines.append(entry.fileName()+QLatin1String("\r\n"));

        sendDtpData(outLines.join(QString()));
    } else {
        //Just one file.
        sendDtpData(info.fileName()+QLatin1String("\r\n"));
    }
}

void FtpPI::doSTOR(const QString &path)
{
    // Store
    if (!vertifyAuthenticated())
        return;
    if (!vertifyPermission(FtpServer::Write))
        return;
    if (!vertifyParamsNotEmpty(path))
        return;

    QString temp = cleanClientPath(path);
    if (temp.startsWith(QLatin1String("/.."))) {
        sendResponse(550, "Path not valid.");
        return;
    }
    QString realPath = m_homeDir + temp;
    QFile *file = new QFile(realPath);
    if (file->exists() && !file->remove()) {
        sendResponse(551, "File could not be overwritten");
        delete file;
        return;
    }

    if (!file->open(QFile::WriteOnly)) {
        sendResponse(551, "File could not be created");
        delete file;
        return;
    }

    recvDtpData(file);
}

void FtpPI::doNOOP(const QString &)
{
    // No Operation
    sendResponse(200, "OK");
}

void FtpPI::doALLO(const QString &param)
{
    // ALLOCATE
    Q_UNUSED(param)
    if (!vertifyAuthenticated())
        return;
    sendResponse(200, "OK");
}

void FtpPI::doRNTO(const QString &path)
{
    if (!vertifyAuthenticated())
        return;
    if (m_lastCmd != QLatin1String("RNFR")) {
        sendResponse(503, "Must followed RNFR");
        return;
    }

    if (!vertifyParamsNotEmpty(path))
        return;

    QString temp = cleanClientPath(path);
    if (temp.startsWith(QLatin1String("/.."))) {
        sendResponse(550, "Path not valid.");
        return;
    }

    QString realPath = m_homeDir + temp;
    qDebug()<<m_filePath<<"-->"<<realPath;
    if (QDir().rename(m_filePath, realPath)) {
        sendResponse(250, "OK.");
    } else {
        sendResponse(553, "Failed.");
    }
}

void FtpPI::doRNFR(const QString &path)
{
    if (!vertifyAuthenticated())
        return;
    if (!vertifyPermission(FtpServer::Exec))
        return;
    if (!vertifyParamsNotEmpty(path))
        return;

    QFileInfo info;
    if (!vertifyClientPathExist(path, info))
        return;

    // Note the difference between absolutePath() and absoluteFilePath()
    m_filePath = info.absoluteFilePath();
    sendResponse(350, "OK.");
}

void FtpPI::doABOR(const QString &)
{
    m_dtp->abortConnection();
    if (m_waitForDtpToConnect)
        m_waitForDtpToConnect = false;
    sendResponse(226, "OK.");
}

void FtpPI::doDELE(const QString &path)
{
    if (!vertifyAuthenticated())
        return;
    if (!vertifyPermission(FtpServer::Exec))
        return;
    if (!vertifyParamsNotEmpty(path))
        return;

    QFileInfo info;
    if (!vertifyClientPathExist(path, info))
        return;

    if (info.isDir()) {
        sendResponse(550, "Only file can be deleted by this command.");
        return;
    }

    if(!QFile(info.filePath()).remove()) {
        sendResponse(450, "Fail to delete the file.");
        return;
    }

    sendResponse(250, "OK.");
}

#ifndef QT_NO_SSL
void FtpPI::doAUTH(const QString &param)
{
    if (!vertifyParamsNotEmpty(param))
        return;

    if (param.toUpper() == QLatin1String("TLS") || param.toUpper() == QLatin1String("SSL")) {
        if (!m_server->d_func()->sslConfiguration.isNull()) {
            sendResponse(234, "Initializing SSL connection.");
            m_socket->setSslConfiguration(m_server->d_func()->sslConfiguration);
            m_socket->startServerEncryption();
        } else {
            sendResponse(534, "Server configure error.");
        }
    } else {
        sendResponse(504, "Command not implemented for this param");
    }
}

void FtpPI::doPROT(const QString &param)
{
    if (!vertifyAuthenticated())
        return;
    if (!vertifyParamsNotEmpty(param))
        return;

    if (param.toUpper() == QLatin1String("C")) {
        sendResponse(200, "Command okay.");
    } else {
        sendResponse(504, "Command not implemented for this param");
    }
}

void FtpPI::doPBSZ(const QString &param)
{
    if (!vertifyAuthenticated())
        return;
    if (!vertifyParamsNotEmpty(param))
        return;

    sendResponse(200, "Command okay.");
}
#endif

void FtpPI::doFEAT(const QString &)
{
    QString out = QStringLiteral("Extensions supported:\r\n");

    if (m_server->codec()->mibEnum() == 106) {//utf8
        //Send the feature only if we are using utf8 now.
        out.append(QLatin1String("UTF8\r\n"));
    }

    out.append(QLatin1String("END"));

    sendResponse(211, out);
}

void FtpPI::doOPTS(const QString &param)
{
    if (param.startsWith("UTF8", Qt::CaseInsensitive)
            || param.startsWith("UTF-8", Qt::CaseInsensitive)) {
        //Note, this option isn't defined in any RFC files.
        //Only make the ftp client provided by Windows explorer happy here.
        if (m_server->codec()->mibEnum() == 106) {//utf8
            sendResponse(200, "Command okay.");
            return;
        }
    }

    sendResponse(504, "Command not implemented for this param.");
}

void FtpPI::doREST(const QString &marker)
{
    // Restart failed transfer
    Q_UNUSED(marker)
    if (!vertifyAuthenticated())
        return;
    sendResponse(350, "OK.");
}

void FtpPI::doPORT(const QString &param)
{
    if (!vertifyAuthenticated())
        return;
    QStringList ps = param.split(QLatin1Char(','));
    if (ps.size() != 6) {
        sendResponse(501, "Syntax error in parameters");
        return;
    }

    QHostAddress addr(QString::fromLatin1("%1.%2.%3.%4").arg(ps[0], ps[1], ps[2], ps[3]));
    quint16 port = ps[4].toInt() * 256 + ps[5].toInt();

    m_dtp->setClientAddress(addr, port);

    sendResponse(200, "OK");
}

void FtpPI::doRETR(const QString &path)
{
    // Retrieve a file
    if (!vertifyAuthenticated())
        return;
    if (!vertifyPermission(FtpServer::Read))
        return;
    if (!vertifyParamsNotEmpty(path))
        return;

    QFileInfo info;
    if (!vertifyClientPathExist(path, info))
        return;

    QFile *f = new QFile(info.filePath());
    if (!f->open(QFile::ReadOnly)) {
        sendResponse(550, "Can not open the file.");
        delete f;
        return;
    }

    sendDtpData(f);
}

void FtpPI::doSIZE(const QString &path)
{
    // Returns the size of a file
    if (!vertifyAuthenticated())
        return;
    if (!vertifyParamsNotEmpty(path))
        return;

    QFileInfo info;
    if (!vertifyClientPathExist(path, info))
        return;

    sendResponse(213, QString::number(info.size()));
}

void FtpPI::doXCUP(const QString &any)
{
    doCDUP(any);
}

void FtpPI::doXPWD(const QString &any)
{
    doPWD(any);
}

void FtpPI::doXMKD(const QString &path)
{
    doMKD(path);
}

void FtpPI::doXRMD(const QString &path)
{
    doRMD(path);
}


void FtpPI::close()
{
    m_socket->close();
}


/**********************************************************************
 *
 * FtpDTP implemenatation
 *
 *********************************************************************/
FtpDTP::FtpDTP(FtpPI *parent)
    :QObject(parent), m_ftpPI(parent)
{
    m_listener = new QTcpServer(this);
    m_dataSocket = 0;
    m_clientPort = 0;
    m_connectionType = CT_Active;
    m_timer = new QTimer(this);

    connect(m_listener, SIGNAL(newConnection()), this, SLOT(onNewSocketConnection()));
    connect(m_timer, SIGNAL(timeout()), this, SLOT(onTimeout()));
}

FtpDTP::~FtpDTP()
{
    cleanUp();
}

FtpDTP::ConnectionType FtpDTP::connectionType() const
{
    return m_connectionType;
}

QTcpSocket::SocketState FtpDTP::state() const
{
    return m_dataSocket ? m_dataSocket->state() : QTcpSocket::UnconnectedState;
}

int FtpDTP::setupListener(const QHostAddress &addr)
{
    m_connectionType = CT_Passive;
    if (!m_listener->isListening() && !m_listener->listen(addr, 0))
        return -1;
    return m_listener->serverPort();
}

void FtpDTP::startConnection()
{
    if (m_connectionType == CT_Active) {
        connectToClient();
    } else {
        //wait for new connection.
        m_timer->start(2000);
    }
}

void FtpDTP::waitForConnection()
{
    if (m_connectionType == CT_Passive || m_listener->isListening())
            m_listener->waitForNewConnection();
}

void FtpDTP::abortConnection()
{
    cleanUp();

    if (m_listener->isListening())
        m_listener->close();
    if (m_dataSocket)
        m_dataSocket->abort();
}

void FtpDTP::setClientAddress(const QHostAddress &host, quint16 port)
{
    m_connectionType = CT_Active;
    m_clientAddr = host;
    m_clientPort = port;
}

void FtpDTP::connectToClient()
{
    //Only for active
    if (m_connectionType == CT_Passive)
        return;

    // bytesFromSocket.clear();
    if (m_dataSocket) {
        delete m_dataSocket;
        m_dataSocket = 0;
    }
    m_dataSocket = new QTcpSocket(this);
    m_dataSocket->bind(20);

    connect(m_dataSocket, SIGNAL(connected()), SLOT(onSocketConnected()));
    connect(m_dataSocket, SIGNAL(readyRead()), SLOT(onSocketReadyRead()));
    connect(m_dataSocket, SIGNAL(error(QAbstractSocket::SocketError)), SLOT(onSocketError(QAbstractSocket::SocketError)));
    connect(m_dataSocket, SIGNAL(disconnected()), SLOT(onSocketConnectionClosed()));
    connect(m_dataSocket, SIGNAL(bytesWritten(qint64)), SLOT(onSocketBytesWritten(qint64)));

    m_dataSocket->connectToHost(m_clientAddr, m_clientPort);
    m_dataSocket->waitForConnected();
#ifdef DEBUG_DTP
    qDebug()<<"Connect to Client: "<<m_clientAddr<<m_clientAddr;
#endif
}

void FtpDTP::onSocketConnected()
{
    emit stateChanged(CS_Connected);
    //Try fulsh the data if exists.
    writeData();
}

void FtpDTP::onSocketReadyRead()
{
    readData();
}

void FtpDTP::onSocketError(QAbstractSocket::SocketError e)
{
#ifdef DEBUG_DTP
        qDebug()<<"socket error";
#endif
    if (e == QTcpSocket::HostNotFoundError)
        emit stateChanged(CS_ClientNotFound);
    else if (e == QTcpSocket::ConnectionRefusedError)
        emit stateChanged(CS_ConnectionRefused);
}

void FtpDTP::onSocketConnectionClosed()
{
#ifdef DEBUG_DTP
    qDebug()<<"Socket disconnected: ";
#endif
    emit stateChanged(CS_Closed);
}

void FtpDTP::onSocketBytesWritten(qint64 /*bytes*/)
{

}

void FtpDTP::onNewSocketConnection()
{
    m_timer->stop();

    m_dataSocket = m_listener->nextPendingConnection();
    connect(m_dataSocket, SIGNAL(connected()), SLOT(onSocketConnected()));
    connect(m_dataSocket, SIGNAL(readyRead()), SLOT(onSocketReadyRead()));
    connect(m_dataSocket, SIGNAL(error(QAbstractSocket::SocketError)), SLOT(onSocketError(QAbstractSocket::SocketError)));
    connect(m_dataSocket, SIGNAL(disconnected()), SLOT(onSocketConnectionClosed()));
    connect(m_dataSocket, SIGNAL(bytesWritten(qint64)), SLOT(onSocketBytesWritten(qint64)));

    if (m_dataSocket->state() == QAbstractSocket::ConnectedState) {
        emit stateChanged(CS_Connected);
        writeData();
    }
#ifdef DEBUG_DTP
    qDebug()<<"New connection come from: "<<m_dataSocket->peerAddress()<<m_dataSocket->peerPort();
#endif
    m_listener->close();
}

void FtpDTP::onTimeout()
{
    m_timer->stop();
    m_listener->close();
    emit stateChanged(CS_ClientNotFound);
}

void FtpDTP::setCommandData(const FtpDtpData &data)
{
    m_data = data;
}

void FtpDTP::writeData()
{
    if (m_data.rw != FtpDtpData::Write)
        return;
#ifdef DEBUG_DTP
        qDebug()<<"writeData";
#endif
    if (!m_dataSocket || m_dataSocket->state() != QTcpSocket::ConnectedState)
        return;

    if (!m_data.data.isEmpty()) {
        m_dataSocket->write(m_data.data);
#ifdef DEBUG_DTP
        qDebug()<<"data send: "<<m_data.data.size();
#endif
    } else if (m_data.device && m_data.device->isReadable()) {
        QByteArray bytes = m_data.device->readAll();
        m_dataSocket->write(bytes);
#ifdef DEBUG_DTP
        qDebug()<<"data send: "<<bytes.size();
#endif
    }

    // Close the socket even there is no data to write. For example, an empty file
    m_dataSocket->close();
    m_data.rw = FtpDtpData::None;
}

void FtpDTP::readData()
{
    if (m_data.rw != FtpDtpData::Read)
        return;
#ifdef DEBUG_DTP
        qDebug()<<"readData";
#endif
    if (m_dataSocket && m_dataSocket->state() == QTcpSocket::ConnectedState
            && m_data.device && m_data.device->isWritable()) {
        m_data.device->write(m_dataSocket->readAll());
    }
}

void FtpDTP::cleanUp()
{
    m_data.data.clear();
    if (m_data.device) {
        m_data.device->close();
        delete m_data.device;
        m_data.device = 0;
    }
    m_data.rw = FtpDtpData::None;
}

/**********************************************************************
 *
 * FtpServer implemenatation
 *
 *********************************************************************/
FtpServer::FtpServer(QObject *parent) :
    QTcpServer(parent), d_ptr(new FtpServerPrivate(this, QDir::currentPath()))
{
}

FtpServer::FtpServer(const QString &rootPath, QObject *parent) :
    QTcpServer(parent), d_ptr(new FtpServerPrivate(this, rootPath))
{
}

FtpServer::~FtpServer()
{
    delete d_ptr;
}

QString FtpServer::rootPath() const
{
    Q_D(const FtpServer);
    return d->rootPath;
}

void FtpServer::setRootPath(const QString &rootPath)
{
    Q_D(FtpServer);
    d->rootPath = QDir(rootPath).absolutePath();
}

QTextCodec *FtpServer::codec() const
{
    Q_D(const FtpServer);
    return d->codec;
}

void FtpServer::setCodec(const char *codecName)
{
    Q_D(FtpServer);
    QTextCodec *c = QTextCodec::codecForName(codecName);
    if (c)
        d->codec = c;
}

#ifndef QT_NO_SSL
void FtpServer::setSslConfiguration(const QSslConfiguration &configuration)
{
    Q_D(FtpServer);
    d->sslConfiguration = configuration;
}
#endif

QString FtpServer::welcomeMessage() const
{
    Q_D(const FtpServer);
    return d->welcome;
}

void FtpServer::setWelcomeMessage(const QString &message)
{
    Q_D(FtpServer);
    d->welcome = message;
}

void FtpServer::addAccount(const QString &user, const QString &passWord, const QString &homeDir, Permissions permissions)
{
    Q_D(FtpServer);
    FtpAccountData account(passWord, homeDir, permissions);
    if (user.toLower() == QLatin1String("anonymous"))
        d->accounts.insert(QString(), account); //Empty user name means anonymous
    else
        d->accounts.insert(user, account);
}

void FtpServer::incomingConnection(qintptr socketDescriptor)
{
    FtpPI *connection = new FtpPI(socketDescriptor, this);
    connect(connection, SIGNAL(finished()), connection, SLOT(deleteLater()));
}

#include "ftpserver.moc"
