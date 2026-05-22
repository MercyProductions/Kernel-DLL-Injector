#pragma once

#include <string>

struct AegisGuiSelection
{
	bool shouldContinue = false;
	bool uiUnavailable = false;
	std::string methodOption;
	std::string methodName;
	std::string statusMessage;
};

AegisGuiSelection RunAegisImGuiGate();
