using Microsoft.AspNetCore.Mvc;

namespace BTCPayServer.Plugins.Depix.Controllers
{
    // Lida com a rota antiga/esperada para configurar carteira on-chain:
    // /stores/{storeId}/onchain/DePix  e /stores/{storeId}/onchain/depix
    [Route("stores/{storeId}/onchain/{crypto}")]
    public class OnChainDePixWalletController : Controller
    {
        [HttpGet]
        public IActionResult HandleOnChain(string storeId, string crypto)
        {
            if (string.IsNullOrEmpty(storeId) || string.IsNullOrEmpty(crypto))
            {
                return Redirect("/stores");
            }

            // Normalizar crypto code para minúsculas e comparar
            if (!crypto.Equals("depix", System.StringComparison.OrdinalIgnoreCase))
            {
                // se não for depix, fallback para a lista de wallets
                return Redirect($"/stores/{storeId}/wallets");
            }

            // Construir walletId no formato usado em outras views: S-{storeId}-{CRYPTOUPPER}
            var walletId = $"S-{storeId}-{crypto.ToUpperInvariant()}";

            // Redirecionar para a página de configurações de Pix/DePix onde normalmente se configura a wallet.
            // Usamos a rota /stores/{storeId}/depix/pixsettings e passamos walletId como query (compatível com a view)
            var target = $"/stores/{storeId}/depix/pixsettings?walletId={System.Net.WebUtility.UrlEncode(walletId)}";
            return Redirect(target);
        }
    }
}
