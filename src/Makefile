CC       := gcc
CFLAGS   := -O2 -Wall -Wextra -std=c11
PKGFLAGS := $(shell pkg-config --cflags gtk+-3.0)
PKGLIBS  := $(shell pkg-config --libs gtk+-3.0)
LDFLAGS  := -lm
TARGET   := entropy
SRC      := entropy.c

# Installation layout
PREFIX   := /usr/local
BINDIR   := $(PREFIX)/bin
DATADIR  := $(PREFIX)/share
APPDIR   := $(DATADIR)/applications
# Icon installed into the hicolor theme so the desktop/taskbar picks it up.
ICONDIR  := $(DATADIR)/icons/hicolor/256x256/apps
ICON_INSTALLED := $(ICONDIR)/entropy.png

.PHONY: all clean run install uninstall

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(PKGFLAGS) -DICON_PATH=\"$(ICON_INSTALLED)\" \
		-o $(TARGET) $(SRC) $(PKGLIBS) $(LDFLAGS)

run: $(TARGET)
	./$(TARGET)

# Requires root: sudo make install
install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	install -d $(DESTDIR)$(ICONDIR)
	install -m 0644 entropy.png $(DESTDIR)$(ICON_INSTALLED)
	install -d $(DESTDIR)$(APPDIR)
	install -m 0644 entropy.desktop $(DESTDIR)$(APPDIR)/entropy.desktop
	-gtk-update-icon-cache -q -t -f $(DATADIR)/icons/hicolor 2>/dev/null || true
	-update-desktop-database -q $(APPDIR) 2>/dev/null || true
	@echo "Installed $(TARGET) to $(BINDIR). Run 'entropy' or launch 'Entropy'."

# Requires root: sudo make uninstall
uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)$(ICON_INSTALLED)
	rm -f $(DESTDIR)$(APPDIR)/entropy.desktop
	-gtk-update-icon-cache -q -t -f $(DATADIR)/icons/hicolor 2>/dev/null || true
	-update-desktop-database -q $(APPDIR) 2>/dev/null || true
	@echo "Uninstalled $(TARGET)."

clean:
	rm -f $(TARGET)
