#pragma once

#include "electronic-id/electronic-id.hpp"

#include <stdexcept>

inline electronic_id::CardInfo::ptr autoSelectSupportedCard() {
    using namespace electronic_id;

    auto cardList = availableSupportedCards();
    if (cardList.empty()) {
        std::cout << "autoSelectSupportedCard(): No smart cards attached" << std::endl;
        throw std::logic_error("autoSelectSupportedCard(): No smart cards attached");
    }

    return  cardList[0];
}
