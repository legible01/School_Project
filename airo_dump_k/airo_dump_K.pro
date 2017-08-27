TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    main.cpp \
    airodumpk.cpp

HEADERS += \
    airodumpk.h
LIBS += -lpcap
