// Cocoa + Metal driver for the urbit event log viewer.
// Builds a native NSApplication programmatically (no Info.plist required) and
// renders a Dear ImGui interface backed by Metal.

#import <Cocoa/Cocoa.h>
#import <Metal/Metal.h>
#import <MetalKit/MetalKit.h>

#include <string>

#include "imgui.h"
#include "imgui_impl_metal.h"
#include "imgui_impl_osx.h"

#include "cli.h"
#include "viewer.h"

static std::string g_initial_path;

// MTKView subclass that swallows keyboard events. ImGui_ImplOSX installs a
// global NSEvent monitor that runs *before* the responder chain, so it
// already sees every keystroke. By overriding keyDown:/keyUp: to do
// nothing (and acceptsFirstResponder=YES so we sit at the head of the
// chain), we stop AppKit from interpreting unhandled keys as "no widget
// wanted this — beep!" on every arrow press.
@interface QuietMTKView : MTKView
@end
@implementation QuietMTKView
- (BOOL)acceptsFirstResponder { return YES; }
- (void)keyDown:(NSEvent*)event       { (void)event; }
- (void)keyUp:(NSEvent*)event         { (void)event; }
- (void)flagsChanged:(NSEvent*)event  { (void)event; }
@end

@interface AppViewController : NSViewController <MTKViewDelegate, NSWindowDelegate>
@property (nonatomic, strong) id<MTLDevice>       device;
@property (nonatomic, strong) id<MTLCommandQueue> commandQueue;
@property (nonatomic, assign) Viewer*             viewer;
@end

@implementation AppViewController

- (instancetype)init {
  self = [super initWithNibName:nil bundle:nil];
  if (!self) return nil;

  _device = MTLCreateSystemDefaultDevice();
  _commandQueue = [_device newCommandQueue];
  if (!_device) {
    NSLog(@"Metal is not supported on this device");
    abort();
  }

  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO& io = ImGui::GetIO();
  // Intentionally NOT enabling NavEnableKeyboard: we want the arrow keys
  // to step through events (handled in Viewer::draw), not jump focus
  // between widgets. Textbox cursor movement still works either way.
  io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
  ImGui::StyleColorsDark();

  ImGui_ImplMetal_Init(_device);

  _viewer = new Viewer();
  if (!g_initial_path.empty()) {
    _viewer->open(g_initial_path);
  }
  return self;
}

- (MTKView*)mtkView { return (MTKView*)self.view; }

- (void)loadView {
  self.view = [[QuietMTKView alloc] initWithFrame:CGRectMake(0, 0, 1280, 800)];
}

- (void)viewDidLoad {
  [super viewDidLoad];
  self.mtkView.device   = self.device;
  self.mtkView.delegate = self;
  ImGui_ImplOSX_Init(self.view);
  [NSApp activateIgnoringOtherApps:YES];
}

- (void)drawInMTKView:(MTKView*)view {
  ImGuiIO& io = ImGui::GetIO();
  io.DisplaySize.x = view.bounds.size.width;
  io.DisplaySize.y = view.bounds.size.height;
  CGFloat scale = view.window.screen.backingScaleFactor ?: NSScreen.mainScreen.backingScaleFactor;
  io.DisplayFramebufferScale = ImVec2(scale, scale);

  id<MTLCommandBuffer> commandBuffer = [self.commandQueue commandBuffer];
  MTLRenderPassDescriptor* desc = view.currentRenderPassDescriptor;
  if (desc == nil) {
    [commandBuffer commit];
    return;
  }

  ImGui_ImplMetal_NewFrame(desc);
  ImGui_ImplOSX_NewFrame(view);
  ImGui::NewFrame();

  // Make our viewer occupy most of the window.
  // Pin the ImGui window to the native window every frame; the macOS
  // window itself handles all moving / resizing.
  ImGui::SetNextWindowPos(ImVec2(0, 0));
  ImGui::SetNextWindowSize(io.DisplaySize);
  _viewer->draw();

  ImGui::Render();
  desc.colorAttachments[0].clearColor = MTLClearColorMake(0.10, 0.11, 0.13, 1.0);
  id<MTLRenderCommandEncoder> enc = [commandBuffer renderCommandEncoderWithDescriptor:desc];
  [enc pushDebugGroup:@"ImGui"];
  ImGui_ImplMetal_RenderDrawData(ImGui::GetDrawData(), commandBuffer, enc);
  [enc popDebugGroup];
  [enc endEncoding];

  [commandBuffer presentDrawable:view.currentDrawable];
  [commandBuffer commit];
}

- (void)mtkView:(MTKView*)view drawableSizeWillChange:(CGSize)size { (void)view; (void)size; }

- (void)viewWillAppear {
  [super viewWillAppear];
  self.view.window.delegate = self;
}

- (void)windowWillClose:(NSNotification*)notification {
  (void)notification;
  delete _viewer;
  _viewer = nullptr;
  ImGui_ImplMetal_Shutdown();
  ImGui_ImplOSX_Shutdown();
  ImGui::DestroyContext();
}

@end

@interface AppDelegate : NSObject <NSApplicationDelegate>
@property (nonatomic, strong) NSWindow* window;
@end

@implementation AppDelegate

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication*)sender {
  (void)sender;
  return YES;
}

- (instancetype)init {
  self = [super init];
  if (!self) return nil;

  AppViewController* root = [[AppViewController alloc] init];
  NSWindowStyleMask style =
      NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
      NSWindowStyleMaskResizable | NSWindowStyleMaskMiniaturizable;
  self.window = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 1280, 800)
                                            styleMask:style
                                              backing:NSBackingStoreBuffered
                                                defer:NO];
  self.window.title = @"urbit event log viewer";
  self.window.contentViewController = root;
  [self.window center];
  [self.window makeKeyAndOrderFront:self];
  return self;
}

@end

int run_gui(const char* initial_path) {
  if (initial_path && *initial_path) g_initial_path = initial_path;
  @autoreleasepool {
    NSApplication* app = [NSApplication sharedApplication];
    [app setActivationPolicy:NSApplicationActivationPolicyRegular];
    AppDelegate* delegate = [[AppDelegate alloc] init];
    [app setDelegate:delegate];
    [app run];
  }
  return 0;
}
