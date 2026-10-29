#include "updateController.h"

#ifndef SANE4EK_BUILD_NUMBER
#define SANE4EK_BUILD_NUMBER 0
#endif
#ifndef SANE4EK_UPDATE_URL
#define SANE4EK_UPDATE_URL "https://api.github.com/repos/shyrik921204-netizen/business-vpn/releases/latest"
#endif

#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QStandardPaths>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSysInfo>
#include <QTimer>
#include <QUrl>

#include "amneziaApplication.h"
#include "logger.h"
#include "core/controllers/gatewayController.h"
#include "core/utils/api/gatewayPayloadBuilder.h"
#include "core/utils/appUiConfig.h"
#include "core/utils/constants/apiConstants.h"
#include "core/utils/constants/apiKeys.h"
#include "core/utils/selfhosted/scriptsRegistry.h"

#if defined(Q_OS_ANDROID)
    #include "platforms/android/android_controller.h"
#endif

namespace
{
    Logger logger("UpdateController");

#if defined(Q_OS_WINDOWS)
    const QLatin1String kInstallerRemoteFileNamePattern("AmneziaVPN_%1_windows_x64.exe");
    const QString kInstallerLocalPath = QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/AmneziaVPN_installer.exe";
#elif defined(Q_OS_MACOS) && !defined(MACOS_NE)
    const QLatin1String kInstallerRemoteFileNamePattern("AmneziaVPN_%1_macos_x64.pkg");
    const QString kInstallerLocalPath = QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/AmneziaVPN.pkg";
#elif defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    const QLatin1String kInstallerRemoteFileNamePattern("AmneziaVPN_%1_linux_x64.run");
    const QString kInstallerLocalPath = QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/AmneziaVPN.run";
#endif

    [[maybe_unused]] QStringList stringListFromJsonValue(const QJsonValue &value)
    {
        QStringList result;
        for (const QJsonValue &item : value.toArray()) {
            const QString text = item.toString();
            if (!text.isEmpty()) {
                result.append(text);
            }
        }
        return result;
    }
}

UpdateController::UpdateController(SecureAppSettingsRepository* appSettingsRepository, QObject *parent)
    : QObject(parent), m_appSettingsRepository(appSettingsRepository)
{
}

QString UpdateController::getVersion() const
{
    return m_version;
}

QString UpdateController::getReleaseDate() const
{
    return m_releaseDate;
}

QString UpdateController::getDescription() const
{
    return m_description;
}

QStringList UpdateController::getTags() const
{
    return m_tags;
}

QStringList UpdateController::getNewFeatures() const
{
    return m_newFeatures;
}

QStringList UpdateController::getImprovements() const
{
    return m_improvements;
}

QStringList UpdateController::getBugFixes() const
{
    return m_bugFixes;
}

UpdateState::State UpdateController::getUpdateState() const
{
    return m_updateState;
}

bool UpdateController::isStoreUpdate() const
{
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    return true;
#elif defined(Q_OS_ANDROID)
    return false; // Sane4ek is distributed as an APK, never through a store
#else
    return false;
#endif
}

void UpdateController::setUpdateState(UpdateState::State state)
{
    if (m_updateState == state) {
        return;
    }
    m_updateState = state;
    emit updateStateChanged();
}

bool UpdateController::isUpdateCheckRunning() const
{
    return m_updateCheckRunning;
}

void UpdateController::setUpdateCheckRunning(bool running)
{
    if (m_updateCheckRunning == running) {
        return;
    }
    m_updateCheckRunning = running;
    emit updateCheckRunningChanged();
}

void UpdateController::checkForUpdates()
{
#if !CLIENT_ENABLE_APP_UPDATES
    return;
#endif

#if !defined(Q_OS_ANDROID)
    // Sane4ek: published releases carry Android APKs only, desktop builds are installed manually
    emit updateNotFound();
    return;
#endif

    if (m_updateCheckRunning) {
        return;
    }
    setUpdateCheckRunning(true);

    // Sane4ek: new versions are GitHub releases of the project repository, tagged "build-<N>".
    // The build number of this binary comes from the CI run number (SANE4EK_BUILD_NUMBER).
    auto *network = new QNetworkAccessManager(this);
    QNetworkRequest request(QUrl(QStringLiteral(SANE4EK_UPDATE_URL)));
    request.setRawHeader("Accept", "application/vnd.github+json");
    request.setRawHeader("User-Agent", "Sane4ek");
    request.setTransferTimeout(20000);

    QNetworkReply *reply = network->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply, network]() {
        reply->deleteLater();
        network->deleteLater();
        setUpdateCheckRunning(false);

        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (status == 404) {
            logger.info() << "No published releases yet";
            emit updateNotFound();
            return;
        }
        if (reply->error() != QNetworkReply::NoError) {
            logger.error() << "Update check failed:" << reply->errorString();
            emit updateCheckFailed();
            return;
        }

        const QJsonObject release = QJsonDocument::fromJson(reply->readAll()).object();
        const QString tag = release.value("tag_name").toString();
        const int build = tag.startsWith("build-") ? tag.mid(6).toInt() : 0;
        if (build <= SANE4EK_BUILD_NUMBER) {
            logger.info() << "No application update available, latest build" << build << "own build" << SANE4EK_BUILD_NUMBER;
            emit updateNotFound();
            return;
        }

        QString apkUrl, universalUrl;
        for (const QJsonValue &v : release.value("assets").toArray()) {
            const QString name = v.toObject().value("name").toString();
            const QString url = v.toObject().value("browser_download_url").toString();
            if (name.endsWith("arm64-v8a.apk")) {
                apkUrl = url;
            } else if (name.endsWith("universal.apk")) {
                universalUrl = url;
            }
        }
        const QString abis = QSysInfo::buildCpuArchitecture();
        if (apkUrl.isEmpty() || !abis.contains("arm64")) {
            apkUrl = universalUrl.isEmpty() ? apkUrl : universalUrl;
        }

        m_version = release.value("name").toString();
        if (m_version.isEmpty()) {
            m_version = tag;
        }
        m_releaseDate = release.value("published_at").toString().left(10);
        m_description = release.value("body").toString();
        m_tags.clear();
        m_newFeatures.clear();
        m_improvements.clear();
        m_bugFixes.clear();
        m_downloadBaseUrl.clear();
        m_releasePageUrl = apkUrl.isEmpty() ? release.value("html_url").toString() : apkUrl;

        logger.info() << "Application update available:" << tag;
        setUpdateState(UpdateState::State::Idle);
        emit updateFound();
    });
}

void UpdateController::openStorePage() const
{
#if defined(Q_OS_IOS)
    QDesktopServices::openUrl(QUrl(QLatin1String(APP_IOS_STORE_URL_FALLBACK)));
#elif defined(MACOS_NE)
    QDesktopServices::openUrl(QUrl(QStringLiteral("https://apps.apple.com/app/id1600529900")));
#elif defined(Q_OS_ANDROID)
    QDesktopServices::openUrl(
            QUrl(QStringLiteral("https://play.google.com/store/apps/details?id=%1").arg(QLatin1String(APP_ANDROID_PACKAGE))));
#endif
}

void UpdateController::startUpdate()
{
    if (isStoreUpdate()) {
        openStorePage();
        return;
    }

#if defined(Q_OS_ANDROID)
    // Sane4ek: download the APK inside the app and install it with the system installer
    if (m_releasePageUrl.isEmpty()) {
        logger.error() << "Release page URL is empty";
        setUpdateState(UpdateState::State::DownloadError);
        return;
    }
    if (m_updateState == UpdateState::State::ReadyToInstall && QFile::exists(m_apkPath)) {
        installUpdate();
        return;
    }
    downloadAndroidApk();
#elif !defined(Q_OS_IOS) && !defined(MACOS_NE)
    downloadInstaller();
#endif
}

QString UpdateController::composeDownloadUrl() const
{
#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
    if (m_downloadBaseUrl.isEmpty() || m_version.isEmpty()) {
        return QString();
    }
    const QString fileName = QString(kInstallerRemoteFileNamePattern).arg(m_version);
    return m_downloadBaseUrl + "/" + fileName;
#else
    return QString();
#endif
}

void UpdateController::downloadInstaller()
{
#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
    if (m_updateState == UpdateState::State::Downloading) {
        return;
    }

    const QString downloadUrl = composeDownloadUrl();
    if (downloadUrl.isEmpty()) {
        logger.error() << "Download URL is empty";
        setUpdateState(UpdateState::State::DownloadError);
        return;
    }

    setUpdateState(UpdateState::State::Downloading);

    QNetworkRequest request;
    request.setTransferTimeout(30000);
    request.setUrl(QUrl(downloadUrl));

    QNetworkReply *reply = amnApp->networkManager()->get(request);

    QObject::connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();

        if (reply->error() != QNetworkReply::NoError) {
            logger.error() << "Installer download failed, network error:" << static_cast<int>(reply->error())
                           << reply->errorString();
            logger.error() << "HTTP status:" << reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            setUpdateState(UpdateState::State::DownloadError);
            return;
        }

        QFile file(kInstallerLocalPath);
        if (!file.open(QIODevice::WriteOnly)) {
            logger.error() << "Failed to open installer file for writing:" << kInstallerLocalPath
                           << "Error:" << file.errorString();
            setUpdateState(UpdateState::State::DownloadError);
            return;
        }

        if (file.write(reply->readAll()) == -1) {
            logger.error() << "Failed to write installer data to file:" << kInstallerLocalPath
                           << "Error:" << file.errorString();
            file.close();
            setUpdateState(UpdateState::State::DownloadError);
            return;
        }

        file.close();
        setUpdateState(UpdateState::State::ReadyToInstall);
    });
#endif
}

#if defined(Q_OS_ANDROID)
void UpdateController::downloadAndroidApk()
{
    if (m_updateState == UpdateState::State::Downloading) {
        return;
    }
    if (!m_releasePageUrl.endsWith(".apk")) {
        // no APK in the release: fall back to the release page
        QDesktopServices::openUrl(QUrl(m_releasePageUrl));
        return;
    }

    const QString dir = QStandardPaths::writableLocation(QStandardPaths::CacheLocation);
    QDir().mkpath(dir);
    m_apkPath = dir + "/sane4ek-update.apk";
    auto *file = new QFile(m_apkPath + ".part", this);
    if (!file->open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        logger.error() << "Cannot write" << file->fileName() << file->errorString();
        delete file;
        setUpdateState(UpdateState::State::DownloadError);
        return;
    }

    m_downloadProgress = 0;
    emit downloadProgressChanged();
    setUpdateState(UpdateState::State::Downloading);

    QNetworkRequest request{QUrl(m_releasePageUrl)};
    request.setRawHeader("User-Agent", "Sane4ek");
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
    request.setTransferTimeout(60000); // no data for a minute

    auto *network = new QNetworkAccessManager(this);
    QNetworkReply *reply = network->get(request);

    connect(reply, &QNetworkReply::readyRead, this, [reply, file]() { file->write(reply->readAll()); });
    connect(reply, &QNetworkReply::downloadProgress, this, [this](qint64 received, qint64 total) {
        const int progress = total > 0 ? static_cast<int>(received * 100 / total) : 0;
        if (progress != m_downloadProgress) {
            m_downloadProgress = progress;
            emit downloadProgressChanged();
        }
    });
    connect(reply, &QNetworkReply::finished, this, [this, reply, network, file]() {
        file->write(reply->readAll());
        file->close();
        reply->deleteLater();
        network->deleteLater();
        file->deleteLater();

        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (reply->error() != QNetworkReply::NoError || status != 200 || file->size() < 1024 * 1024) {
            logger.error() << "Update download failed:" << reply->errorString() << "HTTP" << status;
            QFile::remove(file->fileName());
            setUpdateState(UpdateState::State::DownloadError);
            return;
        }
        QFile::remove(m_apkPath);
        if (!QFile::rename(file->fileName(), m_apkPath)) {
            logger.error() << "Cannot rename the downloaded update";
            setUpdateState(UpdateState::State::DownloadError);
            return;
        }
        logger.info() << "Update downloaded," << QFileInfo(m_apkPath).size() << "bytes";
        setUpdateState(UpdateState::State::ReadyToInstall);
        installUpdate();
    });
}
#endif

void UpdateController::installUpdate()
{
#if defined(Q_OS_ANDROID)
    if (m_updateState == UpdateState::State::ReadyToInstall && QFile::exists(m_apkPath)) {
        AndroidController::instance()->installApk(m_apkPath);
    } else {
        startUpdate();
    }
    return;
#endif
#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
    if (m_updateState != UpdateState::State::ReadyToInstall) {
        logger.error() << "Installer is not downloaded yet";
        return;
    }

    #if defined(Q_OS_WINDOWS)
    runWindowsInstaller(kInstallerLocalPath);
    #elif defined(Q_OS_MACOS) && !defined(MACOS_NE)
    runMacInstaller(kInstallerLocalPath);
    #elif defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    runLinuxInstaller(kInstallerLocalPath);
    #endif
#endif
}

#if defined(Q_OS_WINDOWS)
int UpdateController::runWindowsInstaller(const QString &installerPath)
{
    qint64 pid;
    bool success = QProcess::startDetached(installerPath, QStringList(), QString(), &pid);

    if (success) {
        logger.info() << "Installation process started with PID:" << pid;
    } else {
        logger.error() << "Failed to start installation process";
        return -1;
    }

    return 0;
}
#endif

#if defined(Q_OS_MACOS) && !defined(MACOS_NE)
int UpdateController::runMacInstaller(const QString &installerPath)
{
    // Create temporary directory for extraction
    QTemporaryDir extractDir;
    extractDir.setAutoRemove(false);
    if (!extractDir.isValid()) {
        logger.error() << "Failed to create temporary directory";
        return -1;
    }
    logger.info() << "Temporary directory created:" << extractDir.path();

    // Create script file in the temporary directory
    QString scriptPath = extractDir.path() + "/mac_installer.sh";
    QFile scriptFile(scriptPath);
    if (!scriptFile.open(QIODevice::WriteOnly)) {
        logger.error() << "Failed to create script file";
        return -1;
    }

    // Get script content from registry
    QString scriptContent = amnezia::scriptData(amnezia::ClientScriptType::mac_installer);
    if (scriptContent.isEmpty()) {
        logger.error() << "macOS installer script content is empty";
        scriptFile.close();
        return -1;
    }

    scriptFile.write(scriptContent.toUtf8());
    scriptFile.close();
    logger.info() << "Script file created:" << scriptPath;

    // Make script executable
    QFile::setPermissions(scriptPath, QFile::permissions(scriptPath) | QFile::ExeUser);

    // Start detached process
    qint64 pid;
    bool success =
            QProcess::startDetached("/bin/bash", QStringList() << scriptPath << extractDir.path() << installerPath, extractDir.path(), &pid);

    if (success) {
        logger.info() << "Installation process started with PID:" << pid;
    } else {
        logger.error() << "Failed to start installation process";
        return -1;
    }

    return 0;
}
#endif

#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
int UpdateController::runLinuxInstaller(const QString &installerPath)
{
    QFile::setPermissions(installerPath, QFile::permissions(installerPath) | QFile::ExeUser);

    qint64 pid;
    bool success = QProcess::startDetached(installerPath, QStringList(), QString(), &pid);

    if (success) {
        logger.info() << "Installation process started with PID:" << pid;
    } else {
        logger.error() << "Failed to start installation process";
        return -1;
    }

    return 0;
}
#endif
