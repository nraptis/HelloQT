// main.cpp
#include <QApplication>
#include <QWidget>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QFileDialog>
#include <QMessageBox>
#include <QDir>
#include <vector>
#include "Cipher.h"
#include "CopyCipher.h"
#include "Mersenne.hpp"
#include "ChaCha20Counter.hpp"
#include "AESCounter.hpp"

struct UI {
    // Window
    static constexpr int WindowW = 1024;
    static constexpr int WindowH = 700;

    // Spacing
    static constexpr int PageMargin = 20;
    static constexpr int SectionSpacing = 16;
    static constexpr int RowSpacing = 12;

    // Header
    static constexpr int HeaderHeight = 64;
    static constexpr int HeaderRadius = 8;
    static constexpr int HeaderPadH = 24;
    static constexpr int TitlePt = 20;

    // Fields
    static constexpr int LineEditHeight = 36;
    static constexpr int RightButtonW = 60;
    static constexpr int RightButtonH = 36;

    // Actions
    static constexpr int ActionButtonW = 120;
    static constexpr int ActionButtonH = 40;
    static constexpr int RedSquareSize = 24;

    // Style
    static constexpr int CornerRadius = 12;
};

static void styleBlueButton(QPushButton* b) {
    b->setStyleSheet(QString(
        "QPushButton {"
        "  background:#0A84FF; color:white; border:none;"
        "  border-radius:%1px; padding:6px 12px;"
        "}"
        "QPushButton:pressed { background:#0066DD; }"
    ).arg(UI::CornerRadius));
}
static void styleLine(QLineEdit* e) {
    e->setStyleSheet(
        "QLineEdit { border:1px solid #DDDDDD; border-radius:8px; padding:6px 10px; }"
        "QLineEdit:focus { border:1px solid #0A84FF; }"
    );
}

static QString pickExistingFile(QWidget* parent) {
    return QFileDialog::getOpenFileName(parent, "Choose File", QDir::homePath());
}
static QString pickExistingDirectory(QWidget* parent) {
    return QFileDialog::getExistingDirectory(parent, "Choose Folder", QDir::homePath(),
                                             QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
}
// Try to allow both files *and* folders (portable fallback if native dialog won’t allow both)
static QString pickFileOrDirectory(QWidget* parent) {
    // First try a non-native dialog that allows selecting folders in the view:
    QFileDialog dlg(parent, "Choose File or Folder", QDir::homePath());
    dlg.setOption(QFileDialog::DontUseNativeDialog, true);
    dlg.setFileMode(QFileDialog::ExistingFiles);
    dlg.setNameFilter("All (*.*)");
    dlg.setFilter(QDir::AllEntries | QDir::NoDotAndDotDot | QDir::AllDirs | QDir::Files);
    if (dlg.exec() == QDialog::Accepted) {
        const QStringList sel = dlg.selectedFiles();
        if (!sel.isEmpty()) return sel.first(); // file or directory path (both appear)
    }
    // Fallback: offer a quick choice
    const auto btn = QMessageBox::question(parent, "Pick",
        "Couldn’t choose both with this platform’s dialog.\nPick a file instead?",
        QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
    if (btn == QMessageBox::Yes) return pickExistingFile(parent);
    return pickExistingDirectory(parent);
}

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    QWidget window;
    window.setWindowTitle("File Wizard Pro X");
    window.resize(UI::WindowW, UI::WindowH);

    auto *root = new QVBoxLayout(&window);
    root->setContentsMargins(UI::PageMargin, UI::PageMargin, UI::PageMargin, UI::PageMargin);
    root->setSpacing(UI::SectionSpacing);

    // Header
    auto *header = new QFrame;
    header->setFixedHeight(UI::HeaderHeight);
    header->setStyleSheet(QString("QFrame { background:#EEF0F4; border-radius:%1px; }").arg(UI::HeaderRadius));
    auto *headerLay = new QHBoxLayout(header);
    headerLay->setContentsMargins(UI::HeaderPadH, 0, UI::HeaderPadH, 0);
    auto *title = new QLabel("File Wizard Pro XX");
    QFont tf = title->font(); tf.setPointSize(UI::TitlePt); tf.setBold(true); title->setFont(tf);
    headerLay->addStretch(1);
    headerLay->addWidget(title, 0, Qt::AlignCenter);
    headerLay->addStretch(1);
    root->addWidget(header);

    // Helper to create a row (QLineEdit + right-side button with fixed letter)
    auto makeRow = [&](const QString &placeholder, const QString &letter) {
        auto *row = new QWidget;
        auto *h = new QHBoxLayout(row);
        h->setContentsMargins(0,0,0,0);
        h->setSpacing(UI::RowSpacing);

        auto *edit = new QLineEdit;
        edit->setPlaceholderText(placeholder);
        edit->setFixedHeight(UI::LineEditHeight);
        styleLine(edit);

        auto *btn = new QPushButton(letter);
        styleBlueButton(btn);
        btn->setFixedSize(UI::RightButtonW, UI::RightButtonH);

        h->addWidget(edit, 1);
        h->addWidget(btn, 0, Qt::AlignRight);
        return std::pair<QWidget*, std::pair<QLineEdit*, QPushButton*>>(row, {edit, btn});
    };

    // Four rows
    auto r1 = makeRow("c://user/watever (Pack Up Input Directory Or File)", "A");
    auto r2 = makeRow("c://user/watever (Pack Up Output Directory)",        "B");
    auto r3 = makeRow("c://user/watever (Pack Down Input File)",            "C");
    auto r4 = makeRow("c://user/watever (Pack Down Output Directory)",      "D");
    root->addWidget(r1.first);
    root->addWidget(r2.first);
    root->addWidget(r3.first);
    root->addWidget(r4.first);

    // Actions row
    auto *actions = new QWidget;
    auto *ah = new QHBoxLayout(actions);
    ah->setContentsMargins(0,0,0,0);
    ah->setSpacing(UI::RowSpacing);
    ah->addStretch(1);

    auto *packBtn = new QPushButton("Pack Up");
    styleBlueButton(packBtn);
    packBtn->setFixedSize(UI::ActionButtonW, UI::ActionButtonH);
    ah->addWidget(packBtn);

    auto *red = new QFrame;
    red->setFixedSize(UI::RedSquareSize, UI::RedSquareSize);
    red->setStyleSheet("QFrame { background:#FF2D2F; border-radius:6px; }");
    ah->addWidget(red, 0, Qt::AlignVCenter);

    auto *unpackBtn = new QPushButton("Unpack");
    styleBlueButton(unpackBtn);
    unpackBtn->setFixedSize(UI::ActionButtonW, UI::ActionButtonH);
    ah->addWidget(unpackBtn);

    ah->addStretch(1);
    root->addWidget(actions);

    // ---- Hook up pickers ----
    QObject::connect(r1.second.second, &QPushButton::clicked, &window, [&]{
        const QString p = pickFileOrDirectory(&window);
        if (!p.isEmpty()) r1.second.first->setText(p);
    });
    QObject::connect(r2.second.second, &QPushButton::clicked, &window, [&]{
        const QString p = pickExistingDirectory(&window);
        if (!p.isEmpty()) r2.second.first->setText(p);
    });
    QObject::connect(r3.second.second, &QPushButton::clicked, &window, [&]{
        const QString p = pickExistingFile(&window);
        if (!p.isEmpty()) r3.second.first->setText(p);
    });
    QObject::connect(r4.second.second, &QPushButton::clicked, &window, [&]{
        const QString p = pickExistingDirectory(&window);
        if (!p.isEmpty()) r4.second.first->setText(p);
    });

    // ---- Pack Up: QString -> unsigned char buffer -> QString ----
    QObject::connect(packBtn, &QPushButton::clicked, &window, [&]{
        // 1) read unicode string
        const QString original = r1.second.first->text();

        // 2) convert to a UTF-8 byte array, then to std::vector<unsigned char>
        const QByteArray utf8 = original.toUtf8();
        std::vector<unsigned char> buffer(utf8.begin(), utf8.end());

        // (You now have an array of unsigned chars: buffer.data(), buffer.size())

        // 3) convert back to QString (still treating bytes as UTF-8)
        const QString roundTrip = QString::fromUtf8(reinterpret_cast<const char*>(buffer.data()),
                                                    static_cast<int>(buffer.size()));

        // 4) show confirmation
        QMessageBox::information(&window, "Round Trip",
            QString("Original:\n%1\n\nBytes: %2\n\nRound-trip:\n%3")
                .arg(original)
                .arg(buffer.size())
                .arg(roundTrip));
    });

    window.show();


    ChaCha20Counter c;
    AESCounter m;

    return app.exec();
}
