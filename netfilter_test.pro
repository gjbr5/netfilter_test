TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

LIBS += -lnetfilter_queue

SOURCES += \
        callback.cpp \
        main.cpp

HEADERS += \
    callback.h \
    pkt_hdr.h
