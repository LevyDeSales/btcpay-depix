using System;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;

namespace BTCPayServer.Plugins.Depix.Startup
{
    // IStartupFilter para injetar middleware antes do routing e evitar ambiguidade com endpoints existentes.
    public class DepixRedirectStartupFilter : IStartupFilter
    {
        // Regex para capturar /stores/{storeId}/onchain/depix ou variantes de case
        private static readonly Regex OnChainDepix = new Regex(@"^/stores/(?<storeId>[^/]+)/onchain/(?i:depix)$", RegexOptions.Compiled);

        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
        {
            return app =>
            {
                app.Use(async (context, nextMiddleware) =>
                {
                    var path = context.Request.Path.Value ?? string.Empty;

                    var m = OnChainDepix.Match(path);
                    if (m.Success)
                    {
                        var storeId = m.Groups["storeId"].Value;
                        if (string.IsNullOrEmpty(storeId))
                        {
                            context.Response.Redirect("/stores");
                            return;
                        }

                        // Construir walletId S-{storeId}-DEPIX e redirecionar para pixsettings
                        var walletId = $"S-{storeId}-DEPIX";
                        var target = $"/stores/{storeId}/depix/pixsettings?walletId={Uri.EscapeDataString(walletId)}";

                        context.Response.Redirect(target);
                        return;
                    }

                    await nextMiddleware().ConfigureAwait(false);
                });

                next(app);
            };
        }
    }
}
