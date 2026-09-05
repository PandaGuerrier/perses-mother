//! Le contrat que tout module du démon respecte.
//!
//! Un module est une boucle autonome — capture, filtrage, plus tard un client
//! UDP ou le lancement d'une API — que le [`starter`](crate::starter) démarre
//! dans son propre thread. Le contrat ne dit rien de *ce que* le module fait :
//! seulement comment on l'allume, comment on l'éteint, et comment on sait s'il
//! respire encore.

use std::error::Error;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// Erreur remontée par un module.
///
/// `Send + Sync` parce qu'elle traverse la frontière du thread dans lequel le
/// module tourne : un `Box<dyn Error>` nu ne passerait pas.
pub type ModuleResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

/// Ce que le starter attend d'un module.
///
/// `Send` en supertrait : chaque module est déplacé vers son thread.
pub trait ContractBase: Send {
    /// Nom court, utilisé pour nommer le thread et préfixer les journaux.
    fn name(&self) -> &'static str;

    /// Boucle du module. **Bloque** : ne rend la main que sur erreur fatale.
    ///
    /// Tout ce qui peut échouer — résolution d'interface, connexion à Redis —
    /// se fait ici et non à la construction, pour que le starter soit le seul
    /// endroit qui décide quoi faire d'un module en panne.
    fn start(&mut self) -> ModuleResult<()>;

    /// Demande l'arrêt. Doit pouvoir être appelée depuis un autre thread que
    /// celui de `start`, et rester sans effet si le module est déjà arrêté.
    fn stop(&mut self) -> ModuleResult<()>;

    /// Drapeau de santé, partagé.
    ///
    /// Le starter en garde un clone avant de céder le module à son thread :
    /// c'est son seul lien avec lui une fois la boucle lancée. Le module le
    /// lève quand sa boucle tourne et le baisse en sortant.
    fn health(&self) -> Arc<AtomicBool>;
}
