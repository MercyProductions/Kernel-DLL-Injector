#include "aegis_imgui_gate.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <d3d11.h>
#include <dxgi.h>
#include <filesystem>
#include <string>
#include <vector>
#include <windows.h>
#include <wincodec.h>
#include <wrl/client.h>

#include "imgui.h"
#include "backends/imgui_impl_dx11.h"
#include "backends/imgui_impl_win32.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d3dcompiler.lib")
#pragma comment(lib, "imm32.lib")
#pragma comment(lib, "windowscodecs.lib")

namespace
{
	using Microsoft::WRL::ComPtr;

	constexpr int kWindowWidth = 1150;
	constexpr int kWindowHeight = 720;
	constexpr float kTitleBarHeight = 54.0f;

	constexpr ImU32 kBackground = IM_COL32(5, 7, 10, 255);
	constexpr ImU32 kPanel = IM_COL32(11, 15, 22, 242);
	constexpr ImU32 kPanelLight = IM_COL32(17, 24, 39, 236);
	constexpr ImU32 kBorder = IM_COL32(30, 58, 95, 210);
	constexpr ImU32 kBorderSoft = IM_COL32(50, 96, 150, 88);
	constexpr ImU32 kAccent = IM_COL32(0, 123, 255, 255);
	constexpr ImU32 kBrightBlue = IM_COL32(0, 166, 255, 255);
	constexpr ImU32 kTextWhite = IM_COL32(245, 247, 250, 255);
	constexpr ImU32 kTextMuted = IM_COL32(138, 148, 166, 255);
	constexpr ImU32 kSilver = IM_COL32(201, 209, 217, 255);
	constexpr ImU32 kDanger = IM_COL32(255, 94, 110, 255);

	constexpr std::array<const char*, 4> kProjects = {
		"Select Project",
		"Project Alpha",
		"Project Beta",
		"Local Build",
	};

	struct AegisUiState
	{
		char licenseKey[256] = {};
		bool isLoggedIn = false;
		int selectedProject = 0;
		std::string statusMessage = "Waiting for license key";
		ID3D11ShaderResourceView* aegisLogoTexture = nullptr;
		int logoWidth = 0;
		int logoHeight = 0;
		bool logoLoadAttempted = false;
	};

	ID3D11Device* gD3dDevice = nullptr;
	ID3D11DeviceContext* gD3dDeviceContext = nullptr;
	IDXGISwapChain* gSwapChain = nullptr;
	ID3D11RenderTargetView* gMainRenderTargetView = nullptr;
	HWND gWindow = nullptr;
	bool gResizePending = false;
	UINT gResizeWidth = 0;
	UINT gResizeHeight = 0;

	AegisUiState gUi{};

	ImVec4 ColorVec(ImU32 color)
	{
		return ImGui::ColorConvertU32ToFloat4(color);
	}

	void CreateRenderTarget()
	{
		ID3D11Texture2D* backBuffer = nullptr;
		gSwapChain->GetBuffer(0, IID_PPV_ARGS(&backBuffer));
		if (backBuffer)
		{
			gD3dDevice->CreateRenderTargetView(backBuffer, nullptr, &gMainRenderTargetView);
			backBuffer->Release();
		}
	}

	void CleanupRenderTarget()
	{
		if (gMainRenderTargetView)
		{
			gMainRenderTargetView->Release();
			gMainRenderTargetView = nullptr;
		}
	}

	bool CreateDeviceD3D(HWND hwnd)
	{
		DXGI_SWAP_CHAIN_DESC swapDesc{};
		swapDesc.BufferCount = 2;
		swapDesc.BufferDesc.Width = 0;
		swapDesc.BufferDesc.Height = 0;
		swapDesc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
		swapDesc.BufferDesc.RefreshRate.Numerator = 60;
		swapDesc.BufferDesc.RefreshRate.Denominator = 1;
		swapDesc.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
		swapDesc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
		swapDesc.OutputWindow = hwnd;
		swapDesc.SampleDesc.Count = 1;
		swapDesc.SampleDesc.Quality = 0;
		swapDesc.Windowed = TRUE;
		swapDesc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

		const D3D_FEATURE_LEVEL featureLevels[] = {
			D3D_FEATURE_LEVEL_11_0,
			D3D_FEATURE_LEVEL_10_0,
		};
		D3D_FEATURE_LEVEL featureLevel{};

		HRESULT result = D3D11CreateDeviceAndSwapChain(
			nullptr,
			D3D_DRIVER_TYPE_HARDWARE,
			nullptr,
			0,
			featureLevels,
			2,
			D3D11_SDK_VERSION,
			&swapDesc,
			&gSwapChain,
			&gD3dDevice,
			&featureLevel,
			&gD3dDeviceContext);

		if (result == DXGI_ERROR_UNSUPPORTED)
		{
			result = D3D11CreateDeviceAndSwapChain(
				nullptr,
				D3D_DRIVER_TYPE_WARP,
				nullptr,
				0,
				featureLevels,
				2,
				D3D11_SDK_VERSION,
				&swapDesc,
				&gSwapChain,
				&gD3dDevice,
				&featureLevel,
				&gD3dDeviceContext);
		}

		if (FAILED(result))
			return false;

		CreateRenderTarget();
		return true;
	}

	void CleanupDeviceD3D()
	{
		if (gUi.aegisLogoTexture)
		{
			gUi.aegisLogoTexture->Release();
			gUi.aegisLogoTexture = nullptr;
		}

		CleanupRenderTarget();
		if (gSwapChain)
		{
			gSwapChain->Release();
			gSwapChain = nullptr;
		}
		if (gD3dDeviceContext)
		{
			gD3dDeviceContext->Release();
			gD3dDeviceContext = nullptr;
		}
		if (gD3dDevice)
		{
			gD3dDevice->Release();
			gD3dDevice = nullptr;
		}
	}

	std::string Trim(std::string value)
	{
		value.erase(value.begin(), std::find_if(value.begin(), value.end(), [](unsigned char ch) {
			return !std::isspace(ch);
		}));
		value.erase(std::find_if(value.rbegin(), value.rend(), [](unsigned char ch) {
			return !std::isspace(ch);
		}).base(), value.end());
		return value;
	}

	std::filesystem::path ModuleDirectory()
	{
		wchar_t modulePath[MAX_PATH] = {};
		GetModuleFileNameW(nullptr, modulePath, ARRAYSIZE(modulePath));
		std::filesystem::path path(modulePath);
		path.remove_filename();
		return path;
	}

	std::vector<std::filesystem::path> LogoCandidates()
	{
		std::vector<std::filesystem::path> candidates;
		const std::filesystem::path exeDir = ModuleDirectory();
		const std::filesystem::path currentDir = std::filesystem::current_path();

		auto pushRoot = [&](const std::filesystem::path& root)
		{
			candidates.push_back(root / L"logo(3).png");
			candidates.push_back(root / L"assets" / L"logo(3).png");
		};

		pushRoot(exeDir);
		pushRoot(currentDir);

		std::filesystem::path walk = exeDir;
		for (int i = 0; i < 4 && walk.has_parent_path(); ++i)
		{
			walk = walk.parent_path();
			pushRoot(walk);
		}

		walk = currentDir;
		for (int i = 0; i < 4 && walk.has_parent_path(); ++i)
		{
			walk = walk.parent_path();
			pushRoot(walk);
		}

		return candidates;
	}

	bool LoadTextureFromFile(const wchar_t* filename, ID3D11ShaderResourceView** outSrv, int* outWidth, int* outHeight)
	{
		if (!filename || !outSrv || !outWidth || !outHeight)
			return false;

		*outSrv = nullptr;
		*outWidth = 0;
		*outHeight = 0;

		ComPtr<IWICImagingFactory> factory;
		HRESULT hr = CoCreateInstance(CLSID_WICImagingFactory2, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&factory));
		if (FAILED(hr))
			hr = CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&factory));
		if (FAILED(hr))
			return false;

		ComPtr<IWICBitmapDecoder> decoder;
		hr = factory->CreateDecoderFromFilename(filename, nullptr, GENERIC_READ, WICDecodeMetadataCacheOnDemand, &decoder);
		if (FAILED(hr))
			return false;

		ComPtr<IWICBitmapFrameDecode> frame;
		hr = decoder->GetFrame(0, &frame);
		if (FAILED(hr))
			return false;

		UINT width = 0;
		UINT height = 0;
		frame->GetSize(&width, &height);
		if (width == 0 || height == 0)
			return false;

		ComPtr<IWICFormatConverter> converter;
		hr = factory->CreateFormatConverter(&converter);
		if (FAILED(hr))
			return false;

		hr = converter->Initialize(
			frame.Get(),
			GUID_WICPixelFormat32bppRGBA,
			WICBitmapDitherTypeNone,
			nullptr,
			0.0,
			WICBitmapPaletteTypeCustom);
		if (FAILED(hr))
			return false;

		std::vector<unsigned char> pixels(static_cast<size_t>(width) * static_cast<size_t>(height) * 4);
		hr = converter->CopyPixels(nullptr, width * 4, static_cast<UINT>(pixels.size()), pixels.data());
		if (FAILED(hr))
			return false;

		D3D11_TEXTURE2D_DESC desc{};
		desc.Width = width;
		desc.Height = height;
		desc.MipLevels = 1;
		desc.ArraySize = 1;
		desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
		desc.SampleDesc.Count = 1;
		desc.Usage = D3D11_USAGE_DEFAULT;
		desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

		D3D11_SUBRESOURCE_DATA subResource{};
		subResource.pSysMem = pixels.data();
		subResource.SysMemPitch = width * 4;

		ComPtr<ID3D11Texture2D> texture;
		hr = gD3dDevice->CreateTexture2D(&desc, &subResource, &texture);
		if (FAILED(hr))
			return false;

		D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc{};
		srvDesc.Format = desc.Format;
		srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
		srvDesc.Texture2D.MipLevels = 1;

		hr = gD3dDevice->CreateShaderResourceView(texture.Get(), &srvDesc, outSrv);
		if (FAILED(hr))
			return false;

		*outWidth = static_cast<int>(width);
		*outHeight = static_cast<int>(height);
		return true;
	}

	void LoadAegisLogoTexture()
	{
		if (gUi.logoLoadAttempted || gUi.aegisLogoTexture)
			return;

		gUi.logoLoadAttempted = true;
		for (const auto& candidate : LogoCandidates())
		{
			std::error_code error;
			if (!std::filesystem::exists(candidate, error))
				continue;

			if (LoadTextureFromFile(candidate.c_str(), &gUi.aegisLogoTexture, &gUi.logoWidth, &gUi.logoHeight))
				return;
		}
	}

	void ApplyAegisImGuiStyle()
	{
		ImGui::StyleColorsDark();
		ImGuiStyle& style = ImGui::GetStyle();
		style.WindowRounding = 0.0f;
		style.ChildRounding = 12.0f;
		style.FrameRounding = 8.0f;
		style.PopupRounding = 8.0f;
		style.ScrollbarRounding = 8.0f;
		style.GrabRounding = 8.0f;
		style.WindowBorderSize = 0.0f;
		style.ChildBorderSize = 1.0f;
		style.FrameBorderSize = 1.0f;
		style.WindowPadding = ImVec2(0.0f, 0.0f);
		style.FramePadding = ImVec2(14.0f, 12.0f);
		style.ItemSpacing = ImVec2(12.0f, 14.0f);
		style.ItemInnerSpacing = ImVec2(10.0f, 8.0f);

		ImVec4* colors = style.Colors;
		colors[ImGuiCol_WindowBg] = ColorVec(kBackground);
		colors[ImGuiCol_ChildBg] = ColorVec(kPanel);
		colors[ImGuiCol_Border] = ColorVec(kBorder);
		colors[ImGuiCol_FrameBg] = ImVec4(0.04f, 0.07f, 0.11f, 1.00f);
		colors[ImGuiCol_FrameBgHovered] = ImVec4(0.06f, 0.12f, 0.20f, 1.00f);
		colors[ImGuiCol_FrameBgActive] = ImVec4(0.07f, 0.18f, 0.31f, 1.00f);
		colors[ImGuiCol_Button] = ImVec4(0.00f, 0.29f, 0.68f, 1.00f);
		colors[ImGuiCol_ButtonHovered] = ImVec4(0.00f, 0.50f, 0.95f, 1.00f);
		colors[ImGuiCol_ButtonActive] = ImVec4(0.00f, 0.36f, 0.76f, 1.00f);
		colors[ImGuiCol_Header] = ImVec4(0.06f, 0.14f, 0.25f, 1.00f);
		colors[ImGuiCol_HeaderHovered] = ImVec4(0.00f, 0.34f, 0.70f, 1.00f);
		colors[ImGuiCol_HeaderActive] = ImVec4(0.00f, 0.49f, 0.95f, 1.00f);
		colors[ImGuiCol_PopupBg] = ImVec4(0.04f, 0.06f, 0.10f, 0.98f);
		colors[ImGuiCol_Text] = ColorVec(kTextWhite);
		colors[ImGuiCol_TextDisabled] = ColorVec(kTextMuted);
		colors[ImGuiCol_CheckMark] = ColorVec(kBrightBlue);
	}

	void DrawGlow(ImDrawList* draw, ImVec2 center, float radius, ImU32 color)
	{
		for (int i = 0; i < 5; ++i)
		{
			const float t = static_cast<float>(i) / 4.0f;
			const int alpha = static_cast<int>(34.0f * (1.0f - t));
			draw->AddCircleFilled(center, radius * (1.0f - t * 0.12f), (color & 0x00ffffff) | (alpha << 24), 96);
		}
	}

	void DrawAngularBorder(ImDrawList* draw, ImVec2 min, ImVec2 max, ImU32 color)
	{
		const float notch = 26.0f;
		draw->AddLine(ImVec2(min.x + notch, min.y), ImVec2(max.x - notch, min.y), color, 1.0f);
		draw->AddLine(ImVec2(max.x - notch, min.y), ImVec2(max.x, min.y + notch), color, 1.0f);
		draw->AddLine(ImVec2(max.x, min.y + notch), ImVec2(max.x, max.y - notch), color, 1.0f);
		draw->AddLine(ImVec2(max.x, max.y - notch), ImVec2(max.x - notch, max.y), color, 1.0f);
		draw->AddLine(ImVec2(max.x - notch, max.y), ImVec2(min.x + notch, max.y), color, 1.0f);
		draw->AddLine(ImVec2(min.x + notch, max.y), ImVec2(min.x, max.y - notch), color, 1.0f);
		draw->AddLine(ImVec2(min.x, max.y - notch), ImVec2(min.x, min.y + notch), color, 1.0f);
		draw->AddLine(ImVec2(min.x, min.y + notch), ImVec2(min.x + notch, min.y), color, 1.0f);
	}

	void DrawBackground(ImDrawList* draw, ImVec2 pos, ImVec2 size)
	{
		const ImVec2 end(pos.x + size.x, pos.y + size.y);
		draw->AddRectFilled(pos, end, kBackground);

		for (float x = pos.x - 120.0f; x < end.x + 120.0f; x += 58.0f)
		{
			draw->AddLine(ImVec2(x, pos.y + kTitleBarHeight), ImVec2(x + 190.0f, end.y), IM_COL32(0, 166, 255, 16), 1.0f);
		}
		for (float y = pos.y + kTitleBarHeight + 36.0f; y < end.y; y += 48.0f)
		{
			draw->AddLine(ImVec2(pos.x + 32.0f, y), ImVec2(end.x - 32.0f, y), IM_COL32(95, 125, 160, 12), 1.0f);
		}
		for (float x = pos.x + 34.0f; x < end.x; x += 72.0f)
		{
			draw->AddLine(ImVec2(x, pos.y + kTitleBarHeight), ImVec2(x, end.y - 28.0f), IM_COL32(95, 125, 160, 10), 1.0f);
		}

		DrawGlow(draw, ImVec2(pos.x + 350.0f, pos.y + 260.0f), 250.0f, kAccent);
		draw->AddRect(pos, end, kBorder, 0.0f, 0, 1.0f);
	}

	bool DrawChromeButton(const char* label, ImVec2 size, bool danger = false)
	{
		ImGui::PushStyleColor(ImGuiCol_Button, danger ? ImVec4(0.22f, 0.04f, 0.07f, 0.75f) : ImVec4(0.06f, 0.09f, 0.14f, 0.70f));
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, danger ? ImVec4(0.58f, 0.06f, 0.12f, 0.96f) : ImVec4(0.02f, 0.28f, 0.55f, 0.96f));
		ImGui::PushStyleColor(ImGuiCol_ButtonActive, danger ? ImVec4(0.42f, 0.03f, 0.08f, 1.00f) : ImVec4(0.00f, 0.20f, 0.44f, 1.00f));
		const bool pressed = ImGui::Button(label, size);
		ImGui::PopStyleColor(3);
		return pressed;
	}

	void DrawAegisTitleBar(AegisGuiSelection& selection, bool& done)
	{
		ImDrawList* draw = ImGui::GetWindowDrawList();
		const ImVec2 pos = ImGui::GetWindowPos();
		const float width = ImGui::GetWindowSize().x;

		draw->AddRectFilled(pos, ImVec2(pos.x + width, pos.y + kTitleBarHeight), IM_COL32(7, 10, 15, 245));
		draw->AddLine(ImVec2(pos.x + 18.0f, pos.y + kTitleBarHeight - 1.0f), ImVec2(pos.x + width - 18.0f, pos.y + kTitleBarHeight - 1.0f), IM_COL32(0, 166, 255, 80), 1.0f);
		draw->AddRectFilled(ImVec2(pos.x + 24.0f, pos.y + 18.0f), ImVec2(pos.x + 52.0f, pos.y + 36.0f), IM_COL32(0, 123, 255, 34));
		draw->AddRect(ImVec2(pos.x + 24.0f, pos.y + 18.0f), ImVec2(pos.x + 52.0f, pos.y + 36.0f), kBrightBlue, 0.0f, 0, 1.0f);

		ImGui::SetCursorScreenPos(ImVec2(pos.x + 66.0f, pos.y + 14.0f));
		ImGui::TextColored(ColorVec(kTextWhite), "AEGIS");
		ImGui::SameLine();
		ImGui::TextColored(ColorVec(kTextMuted), "Project Loader");

		ImGui::SetCursorScreenPos(ImVec2(pos.x, pos.y));
		ImGui::InvisibleButton("##titlebar-drag", ImVec2(width - 166.0f, kTitleBarHeight));
		if (ImGui::IsItemActive() && ImGui::IsMouseDragging(ImGuiMouseButton_Left) && gWindow && !IsZoomed(gWindow))
		{
			RECT rect{};
			GetWindowRect(gWindow, &rect);
			const ImVec2 delta = ImGui::GetIO().MouseDelta;
			SetWindowPos(gWindow, nullptr, rect.left + static_cast<int>(delta.x), rect.top + static_cast<int>(delta.y), 0, 0, SWP_NOSIZE | SWP_NOZORDER);
		}

		ImGui::SetCursorScreenPos(ImVec2(pos.x + width - 148.0f, pos.y + 12.0f));
		if (DrawChromeButton("-", ImVec2(38.0f, 30.0f)))
			ShowWindow(gWindow, SW_MINIMIZE);
		ImGui::SameLine(0.0f, 8.0f);
		if (DrawChromeButton(IsZoomed(gWindow) ? "REST" : "MAX", ImVec2(44.0f, 30.0f)))
			ShowWindow(gWindow, IsZoomed(gWindow) ? SW_RESTORE : SW_MAXIMIZE);
		ImGui::SameLine(0.0f, 8.0f);
		if (DrawChromeButton("X", ImVec2(38.0f, 30.0f), true))
		{
			selection.shouldContinue = false;
			done = true;
		}
	}

	void DrawSectionTitle(const char* title)
	{
		ImGui::TextColored(ColorVec(kSilver), "%s", title);
		ImDrawList* draw = ImGui::GetWindowDrawList();
		const ImVec2 min = ImGui::GetItemRectMin();
		const ImVec2 max = ImGui::GetItemRectMax();
		draw->AddLine(ImVec2(min.x, max.y + 8.0f), ImVec2(min.x + 150.0f, max.y + 8.0f), kBrightBlue, 1.0f);
	}

	void DrawLogoFallback(ImVec2 center)
	{
		ImDrawList* draw = ImGui::GetWindowDrawList();
		const float size = 110.0f;
		draw->AddNgonFilled(center, size, IM_COL32(0, 123, 255, 34), 6);
		draw->AddNgon(center, size, kBrightBlue, 6, 2.0f);
		draw->AddText(ImVec2(center.x - 28.0f, center.y - 12.0f), kTextWhite, "AEGIS");
	}

	void DrawLicensePanel()
	{
		const ImVec2 panelPos = ImGui::GetCursorScreenPos();
		const ImVec2 panelSize = ImGui::GetContentRegionAvail();
		ImDrawList* draw = ImGui::GetWindowDrawList();
		draw->AddRectFilled(panelPos, ImVec2(panelPos.x + panelSize.x, panelPos.y + panelSize.y), kPanel, 12.0f);
		DrawAngularBorder(draw, panelPos, ImVec2(panelPos.x + panelSize.x, panelPos.y + panelSize.y), kBorder);

		ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0, 0, 0, 0));
		ImGui::BeginChild("##license-panel", panelSize, false, ImGuiWindowFlags_NoScrollbar);
		ImGui::SetCursorPos(ImVec2(36.0f, 30.0f));
		DrawSectionTitle("LICENSE KEY LOGIN");

		const float panelWidth = ImGui::GetWindowSize().x;
		const float logoSize = 292.0f;
		const ImVec2 logoCenter(panelPos.x + panelWidth * 0.5f, panelPos.y + 218.0f);
		DrawGlow(draw, logoCenter, 174.0f, kBrightBlue);

		if (gUi.aegisLogoTexture)
		{
			ImGui::SetCursorScreenPos(ImVec2(logoCenter.x - logoSize * 0.5f, logoCenter.y - logoSize * 0.5f));
			ImGui::Image((ImTextureID)(intptr_t)gUi.aegisLogoTexture, ImVec2(logoSize, logoSize));
		}
		else
		{
			DrawLogoFallback(logoCenter);
		}

		const float inputWidth = 500.0f;
		const float inputX = (panelWidth - inputWidth) * 0.5f;
		ImGui::SetCursorPos(ImVec2(inputX, 394.0f));
		ImGui::PushItemWidth(inputWidth);
		const bool submitted = ImGui::InputTextWithHint(
			"##license-key",
			"Enter license key",
			gUi.licenseKey,
			IM_ARRAYSIZE(gUi.licenseKey),
			ImGuiInputTextFlags_Password | ImGuiInputTextFlags_EnterReturnsTrue);
		ImGui::PopItemWidth();

		ImGui::SetCursorPos(ImVec2(inputX, 452.0f));
		if (ImGui::Button("LOGIN", ImVec2(inputWidth, 48.0f)) || submitted)
		{
			if (!Trim(gUi.licenseKey).empty())
			{
				gUi.isLoggedIn = true;
				gUi.statusMessage = "License accepted";
			}
			else
			{
				gUi.isLoggedIn = false;
				gUi.statusMessage = "Invalid license key";
			}
		}

		ImGui::SetCursorPos(ImVec2(inputX, 516.0f));
		ImGui::TextColored(ColorVec(kTextMuted), "Secure & Encrypted Connection");
		ImGui::SetCursorPos(ImVec2(inputX, 544.0f));
		ImGui::TextColored(ColorVec(gUi.isLoggedIn ? kBrightBlue : (gUi.statusMessage == "Invalid license key" ? kDanger : kSilver)), "%s", gUi.statusMessage.c_str());
		ImGui::EndChild();
		ImGui::PopStyleColor();
	}

	void DrawProjectLoadPanel(AegisGuiSelection& selection, bool& done)
	{
		const ImVec2 panelPos = ImGui::GetCursorScreenPos();
		const ImVec2 panelSize = ImGui::GetContentRegionAvail();
		ImDrawList* draw = ImGui::GetWindowDrawList();
		draw->AddRectFilled(panelPos, ImVec2(panelPos.x + panelSize.x, panelPos.y + panelSize.y), kPanelLight, 12.0f);
		DrawAngularBorder(draw, panelPos, ImVec2(panelPos.x + panelSize.x, panelPos.y + panelSize.y), kBorder);

		ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0, 0, 0, 0));
		ImGui::BeginChild("##project-panel", panelSize, false, ImGuiWindowFlags_NoScrollbar);
		ImGui::SetCursorPos(ImVec2(32.0f, 30.0f));
		DrawSectionTitle("LOAD PROJECT");

		const float controlWidth = 340.0f;
		const float controlX = (ImGui::GetWindowSize().x - controlWidth) * 0.5f;
		ImGui::SetCursorPos(ImVec2(controlX, 170.0f));
		ImGui::PushItemWidth(controlWidth);
		if (ImGui::BeginCombo("##project-combo", kProjects[gUi.selectedProject]))
		{
			for (int i = 0; i < static_cast<int>(kProjects.size()); ++i)
			{
				const bool selected = gUi.selectedProject == i;
				if (ImGui::Selectable(kProjects[i], selected))
				{
					gUi.selectedProject = i;
					if (i == 0 && gUi.isLoggedIn)
						gUi.statusMessage = "Select a project";
				}
				if (selected)
					ImGui::SetItemDefaultFocus();
			}
			ImGui::EndCombo();
		}
		ImGui::PopItemWidth();

		ImGui::SetCursorPos(ImVec2(controlX, 236.0f));
		if (ImGui::Button("LOAD", ImVec2(controlWidth, 50.0f)))
		{
			if (!gUi.isLoggedIn)
			{
				gUi.statusMessage = "Login required";
			}
			else if (gUi.selectedProject == 0)
			{
				gUi.statusMessage = "Select a project";
			}
			else
			{
				gUi.statusMessage = "Project loaded";
				selection.shouldContinue = true;
				selection.methodName = kProjects[gUi.selectedProject];
				done = true;
			}
		}

		ImGui::SetCursorPos(ImVec2(controlX, 314.0f));
		ImGui::TextColored(ColorVec(kTextMuted), "Status");
		ImGui::SetCursorPos(ImVec2(controlX, 340.0f));
		ImGui::TextColored(ColorVec(gUi.statusMessage == "Project loaded" || gUi.statusMessage == "License accepted" ? kBrightBlue : kSilver), "%s", gUi.statusMessage.c_str());

		const ImVec2 min = ImVec2(panelPos.x + 30.0f, panelPos.y + panelSize.y - 104.0f);
		const ImVec2 max = ImVec2(panelPos.x + panelSize.x - 30.0f, panelPos.y + panelSize.y - 58.0f);
		draw->AddRect(min, max, kBorderSoft, 7.0f, 0, 1.0f);
		draw->AddLine(ImVec2(min.x + 18.0f, min.y + 23.0f), ImVec2(max.x - 18.0f, min.y + 23.0f), IM_COL32(0, 166, 255, 48), 1.0f);
		ImGui::SetCursorScreenPos(ImVec2(min.x + 20.0f, min.y + 14.0f));
		ImGui::TextColored(ColorVec(kTextMuted), "AUTH GATED - LOCAL SESSION");

		ImGui::EndChild();
		ImGui::PopStyleColor();
	}

	void RenderLoginLoaderScreen(AegisGuiSelection& selection, bool& done)
	{
		LoadAegisLogoTexture();

		const ImGuiViewport* viewport = ImGui::GetMainViewport();
		ImGui::SetNextWindowPos(viewport->WorkPos);
		ImGui::SetNextWindowSize(viewport->WorkSize);
		ImGui::Begin("Aegis Loader", nullptr,
			ImGuiWindowFlags_NoDecoration |
			ImGuiWindowFlags_NoMove |
			ImGuiWindowFlags_NoResize |
			ImGuiWindowFlags_NoSavedSettings |
			ImGuiWindowFlags_NoScrollbar |
			ImGuiWindowFlags_NoScrollWithMouse);

		const ImVec2 windowPos = ImGui::GetWindowPos();
		const ImVec2 windowSize = ImGui::GetWindowSize();
		DrawBackground(ImGui::GetWindowDrawList(), windowPos, windowSize);
		DrawAegisTitleBar(selection, done);

		const float margin = 34.0f;
		const float gap = 30.0f;
		const float contentY = kTitleBarHeight + 28.0f;
		const float contentH = windowSize.y - contentY - 34.0f;
		const float contentW = windowSize.x - margin * 2.0f;
		const float leftW = contentW * 0.58f;
		const float rightW = contentW - leftW - gap;

		ImGui::SetCursorPos(ImVec2(margin, contentY));
		ImGui::BeginChild("##left-shell", ImVec2(leftW, contentH), false, ImGuiWindowFlags_NoScrollbar);
		DrawLicensePanel();
		ImGui::EndChild();

		ImGui::SameLine(0.0f, gap);
		ImGui::BeginChild("##right-shell", ImVec2(rightW, contentH), false, ImGuiWindowFlags_NoScrollbar);
		DrawProjectLoadPanel(selection, done);
		ImGui::EndChild();

		ImGui::End();
	}

	LRESULT WINAPI WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
	{
		if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wParam, lParam))
			return true;

		switch (msg)
		{
		case WM_SIZE:
			if (wParam != SIZE_MINIMIZED)
			{
				gResizeWidth = static_cast<UINT>(LOWORD(lParam));
				gResizeHeight = static_cast<UINT>(HIWORD(lParam));
				gResizePending = true;
			}
			return 0;
		case WM_SYSCOMMAND:
			if ((wParam & 0xfff0) == SC_KEYMENU)
				return 0;
			break;
		case WM_DESTROY:
			PostQuitMessage(0);
			return 0;
		default:
			break;
		}

		return DefWindowProcW(hwnd, msg, wParam, lParam);
	}
}

AegisGuiSelection RunAegisImGuiGate()
{
	AegisGuiSelection selection{};

	const HRESULT comResult = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
	const bool shouldCoUninitialize = SUCCEEDED(comResult);

	ImGui_ImplWin32_EnableDpiAwareness();
	const WNDCLASSEXW windowClass = {
		sizeof(WNDCLASSEXW),
		CS_CLASSDC,
		WndProc,
		0L,
		0L,
		GetModuleHandleW(nullptr),
		nullptr,
		nullptr,
		nullptr,
		nullptr,
		L"AegisLoaderImGuiGate",
		nullptr
	};
	RegisterClassExW(&windowClass);

	const int screenW = GetSystemMetrics(SM_CXSCREEN);
	const int screenH = GetSystemMetrics(SM_CYSCREEN);
	const int windowX = (screenW - kWindowWidth) / 2;
	const int windowY = (screenH - kWindowHeight) / 2;

	gWindow = CreateWindowW(
		windowClass.lpszClassName,
		L"Aegis Loader",
		WS_POPUP | WS_MINIMIZEBOX,
		windowX,
		windowY,
		kWindowWidth,
		kWindowHeight,
		nullptr,
		nullptr,
		windowClass.hInstance,
		nullptr);

	if (!gWindow || !CreateDeviceD3D(gWindow))
	{
		CleanupDeviceD3D();
		if (gWindow)
			DestroyWindow(gWindow);
		UnregisterClassW(windowClass.lpszClassName, windowClass.hInstance);
		if (shouldCoUninitialize)
			CoUninitialize();

		selection.shouldContinue = true;
		selection.uiUnavailable = true;
		selection.statusMessage = "ImGui initialization failed; falling back to console flow.";
		return selection;
	}

	ShowWindow(gWindow, SW_SHOWDEFAULT);
	UpdateWindow(gWindow);

	IMGUI_CHECKVERSION();
	ImGui::CreateContext();
	ImGuiIO& io = ImGui::GetIO();
	io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

	ApplyAegisImGuiStyle();

	ImGui_ImplWin32_Init(gWindow);
	ImGui_ImplDX11_Init(gD3dDevice, gD3dDeviceContext);

	bool done = false;
	while (!done)
	{
		MSG msg;
		while (PeekMessageW(&msg, nullptr, 0U, 0U, PM_REMOVE))
		{
			TranslateMessage(&msg);
			DispatchMessageW(&msg);
			if (msg.message == WM_QUIT)
				done = true;
		}

		if (done)
			break;

		if (gResizePending && gResizeWidth != 0 && gResizeHeight != 0)
		{
			CleanupRenderTarget();
			gSwapChain->ResizeBuffers(0, gResizeWidth, gResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
			gResizePending = false;
			CreateRenderTarget();
		}

		ImGui_ImplDX11_NewFrame();
		ImGui_ImplWin32_NewFrame();
		ImGui::NewFrame();

		RenderLoginLoaderScreen(selection, done);

		ImGui::Render();
		const float clearColor[4] = { 0.019f, 0.027f, 0.039f, 1.00f };
		gD3dDeviceContext->OMSetRenderTargets(1, &gMainRenderTargetView, nullptr);
		gD3dDeviceContext->ClearRenderTargetView(gMainRenderTargetView, clearColor);
		ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
		gSwapChain->Present(1, 0);
	}

	ImGui_ImplDX11_Shutdown();
	ImGui_ImplWin32_Shutdown();
	ImGui::DestroyContext();

	CleanupDeviceD3D();
	DestroyWindow(gWindow);
	gWindow = nullptr;
	UnregisterClassW(windowClass.lpszClassName, windowClass.hInstance);
	if (shouldCoUninitialize)
		CoUninitialize();

	return selection;
}
