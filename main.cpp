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

using namespace pcsc_cpp;
using namespace electronic_id;
using pcsc_cpp::string_t;

QString getCertificate(const CardInfo::ptr& card,
                       const CertificateType certificateType)
{
    const auto certificateBytes = card->eid().getCertificate(certificateType);

    auto certificateDer = QByteArray(reinterpret_cast<const char*>(certificateBytes.data()),
                                     int(certificateBytes.size()));
    auto certificate = QSslCertificate(certificateDer, QSsl::Der);

    return certificate.toText();
}

int main()
{
    std::cout << "*** START ***" << std::endl;


    auto cardList = electronic_id::availableSupportedCards();
    std::cout << "Checking cardlist" << std::endl;
    if (cardList.empty()) {
        std::cout << "CardList is empty" << std::endl;
        throw std::logic_error("test::autoSelectSupportedCard(): No smart cards attached");
    }

    const auto cardInfo = cardList[0];
    /*
    const std::wstring reader_name = cardInfo->reader().name;
    const std::string eid_name = cardInfo->eid().name();
    std::wcout << "Reader: " << reader_name << std::endl;
    std::cout << "Card: " << eid_name << std::endl;
    std::cout << std::endl;


    std::cout << "*** Signing cert start ***" << std::endl;
    const QString signingCert = getCertificate(cardInfo, CertificateType::SIGNING);
    std::cout << signingCert.toStdString() << std::endl;
    std::cout << "*** Signing cert end ***" << std::endl;

    std::cout << "*** Auth cert start ***" << std::endl;
    const QString authCert = getCertificate(cardInfo, CertificateType::AUTHENTICATION);
    std::cout << authCert.toStdString() << std::endl;
    std::cout << "*** Auth cert end ***" << std::endl;
     */

    byte_vector cert = cardInfo->eid().getCertificate(CertificateType::SIGNING);
    std::cout << "*** got signing cert ***" << std::endl;
    const HashAlgorithm hashAlgo = electronic_id::HashAlgorithm::SHA256;
    const byte_vector pin = byte_vector {'1', '2', '3', '4'};
    const byte_vector dataToSign = {'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!'};
    const byte_vector hash = calculateDigest(hashAlgo, dataToSign);
    std::cout << "*** trying to sign ***" << std::endl;
    auto signature = cardInfo->eid().signWithSigningKey(pin, hash, hashAlgo);

    std::cout << "Signing signature: " << pcsc_cpp::bytes2hexstr(signature.first) << std::endl;

    if (!verify(hashAlgo, cert, dataToSign, signature.first, false)) {
        std::cout << "Signature is invalid!!!!!!!" << std::endl;
    }

    std::cout << "*** END ***" << std::endl;
    return  0;
}