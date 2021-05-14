using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

using Xabbo.Messages;
using Xabbo.Interceptor;
using Xabbo.Interceptor.GEarth;

namespace Xabbo.GEarth
{
    /// <summary>
    /// A base implementation for a G-Earth extension.
    /// </summary>
    public abstract class GEarthExtension : INotifyPropertyChanged
    {
        protected bool Set<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
        {
            if (EqualityComparer<T>.Default.Equals(field, value))
            {
                return false;
            }
            else
            {
                field = value;
                RaisePropertyChanged(propertyName);
                return true;
            }
        }

        protected virtual void RaisePropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        public IMessageManager Messages { get; }
        public GEarthRemoteInterceptor Interceptor { get; }

        public Incoming In => Messages.In;
        public Outgoing Out => Messages.Out;

        public bool IsInterceptorConnected => Interceptor.IsInterceptorConnected;
        public bool IsGameConnected => Interceptor.IsConnected;

        /// <summary>
        /// Sends a message to the client or server depending on the header destination.
        /// </summary>
        public Task SendAsync(Header header, params object[] values) => Interceptor.SendAsync(header, values);
        /// <summary>
        /// Sends a message to the client or server depending on the header destination.
        /// </summary>
        public Task SendAsync(IReadOnlyPacket packet) => Interceptor.SendAsync(packet);
        /// <summary>
        /// Sends a message to the server.
        /// </summary>
        public Task SendToServerAsync(Header header, params object[] values) => Interceptor.SendToServerAsync(header, values);
        /// <summary>
        /// Sends a message to the server.
        /// </summary>
        public Task SendToServerAsync(IReadOnlyPacket packet) => Interceptor.SendToServerAsync(packet);
        /// <summary>
        /// Sends a message to the client.
        /// </summary>
        public Task SendToClientAsync(Header header, params object[] values) => Interceptor.SendToClientAsync(header, values);
        /// <summary>
        /// Sends a message to the client.
        /// </summary>
        public Task SendToClientAsync(IReadOnlyPacket packet) => Interceptor.SendToClientAsync(packet);

        public GEarthExtension(GEarthOptions options, int port)
        {
            Messages = new UnifiedMessageManager("messages.ini");
            Interceptor = new GEarthRemoteInterceptor(Messages, options, port);

            Interceptor.InterceptorConnected += OnInterceptorConnected;
            Interceptor.Initialized += OnInterceptorInitialized;
            Interceptor.Clicked += OnClicked;
            Interceptor.Connected += OnGameConnected;
            Interceptor.Intercepted += OnIntercepted;
            Interceptor.Disconnected += OnGameDisconnected;
            Interceptor.InterceptorDisconnected += OnInterceptorDisconnected;
        }

        public Task RunAsync() => Interceptor.RunAsync();
        public void Stop() => Interceptor.Stop();

        protected virtual void OnInterceptorConnected(object? sender, EventArgs e)
        {
            RaisePropertyChanged(nameof(IsInterceptorConnected));
        }
        protected virtual void OnInterceptorInitialized(object? sender, EventArgs e) { }
        protected virtual void OnClicked(object? sender, EventArgs e) { }
        protected virtual void OnGameConnected(object? sender, GameConnectedEventArgs e)
        {
            Interceptor.Dispatcher.Bind(this);
            RaisePropertyChanged(nameof(IsGameConnected));
        }
        protected virtual void OnGameDisconnected(object? sender, EventArgs e)
        {
            Interceptor.Dispatcher.Release(this);
            RaisePropertyChanged(nameof(IsGameConnected));
        }
        protected virtual void OnIntercepted(object? sender, InterceptArgs e) { }
        protected virtual void OnInterceptorDisconnected(object? sender, EventArgs e)
        {
            RaisePropertyChanged(nameof(IsInterceptorConnected));
            RaisePropertyChanged(nameof(IsGameConnected));
        }
    }
}
