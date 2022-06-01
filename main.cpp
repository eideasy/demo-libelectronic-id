#include <electronic-id/electronic-id.hpp>
#include <pcsc-cpp/pcsc-cpp.hpp>
#include "pcsc-cpp/pcsc-cpp-utils.hpp"
#include <iostream>
#include <string>
#include <QApplication>
#include <QByteArray>
#include <QSslCertificate>
#include <QSsl>
#include <QDebug>
#include "./verify.hpp"
#include "./selectcard.hpp"

using namespace pcsc_cpp;
using namespace electronic_id;
using pcsc_cpp::string_t;

QString certBytesToText(byte_vector certificateBytes)
{
    auto certificateDer = QByteArray(reinterpret_cast<const char*>(certificateBytes.data()),
                                     int(certificateBytes.size()));
    auto certificate = QSslCertificate(certificateDer, QSsl::Der);

    return certificate.toText();
}

int main()
{
    std::cout << "*** START ***" << std::endl;

    auto cardInfo = autoSelectSupportedCard();

    //const auto reader_name = cardInfo->reader().name;
    //qDebug() << "Reader: " << cardInfo->reader().name;
    std::cout << "Selected card: " << cardInfo->eid().name() << std::endl;
    std::cout << std::endl;

    const byte_vector dataToSign = {'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!'};

    // Test signing
    byte_vector signingCert = cardInfo->eid().getCertificate(CertificateType::SIGNING);
    std::cout << "*** Signing cert start ***" << std::endl;
    const QString signingCertString = certBytesToText(signingCert);
    std::cout << signingCertString.toStdString() << std::endl;
    std::cout << "*** Signing cert end ***" << std::endl;

    const HashAlgorithm hashAlgo = electronic_id::HashAlgorithm::SHA256;
    const byte_vector pin = byte_vector {'1', '2', '3', '4'};
    const byte_vector hash = calculateDigest(hashAlgo, dataToSign);
    std::cout << "*** trying to sign ***" << std::endl;
    auto signature = cardInfo->eid().signWithSigningKey(pin, hash, hashAlgo);

    std::cout << "Signing signature: " << pcsc_cpp::bytes2hexstr(signature.first) << std::endl;

    if (!verify(hashAlgo, signingCert, dataToSign, signature.first, false)) {
        std::cout << "Signature is invalid!!!!!!!" << std::endl;
    }

    // test authentication
    byte_vector authCert = cardInfo->eid().getCertificate(CertificateType::AUTHENTICATION);
    std::cout << "*** Auth cert start ***" << std::endl;
    const QString authCertString = certBytesToText(authCert);
    std::cout << authCertString.toStdString() << std::endl;
    std::cout << "*** Auth cert end ***" << std::endl;

    std::cout << "Does the reader have a PIN-pad? "
              << (cardInfo->eid().smartcard().readerHasPinPad() ? "yes" : "no") << std::endl;

    if (cardInfo->eid().authSignatureAlgorithm() != JsonWebSignatureAlgorithm::ES384
        && cardInfo->eid().authSignatureAlgorithm() != JsonWebSignatureAlgorithm::RS256
        && cardInfo->eid().authSignatureAlgorithm() != JsonWebSignatureAlgorithm::PS256) {
        // TODO: Add other algorithms as required.
        std::cout << "ERROR: authenticate: Only ES384, RS256 and PS256 signature algorithm currently supported" << std::endl;
        throw std::runtime_error(
                "TEST authenticate: Only ES384, RS256 and PS256 signature algorithm "
                "currently supported");
    }

    std::cout << "*** auth start ***" << std::endl;
    const byte_vector authenticationPin = byte_vector {'1', '2', '3', '4'};
    const JsonWebSignatureAlgorithm authHashAlgo = cardInfo->eid().authSignatureAlgorithm();
    const byte_vector authHash = calculateDigest(authHashAlgo.hashAlgorithm(), dataToSign);
    auto authSignature = cardInfo->eid().signWithAuthKey(authenticationPin, authHash);

    std::cout << "Authentication signature: " << pcsc_cpp::bytes2hexstr(authSignature) << std::endl;

    if (!verify(authHashAlgo.hashAlgorithm(), authCert, dataToSign, authSignature,
                authHashAlgo == JsonWebSignatureAlgorithm::PS256)) {
        throw std::runtime_error("Signature is invalid");
    }

    std::cout << "*** END ***" << std::endl;
    return  0;
}