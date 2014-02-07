TARGET = sslserver

include(../../src/src.pri)

SOURCES += main.cpp

CONFIG   += console
CONFIG   -= app_bundle

RESOURCES += res.qrc
