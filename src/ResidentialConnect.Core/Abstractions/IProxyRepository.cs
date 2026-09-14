using ResidentialConnect.Core.Models;

namespace ResidentialConnect.Core.Abstractions;

/// <summary>
/// CRUD + import storage for <see cref="ProxyProfile"/> entries. Implementations
/// persist only non-secret fields (see <see cref="ProxyProfile.CredentialRef"/>);
/// passwords always flow through <see cref="ICredentialStore"/> instead.
/// </summary>
public interface IProxyRepository
{
    IReadOnlyList<ProxyProfile> GetAll();

    ProxyProfile? GetById(Guid id);

    /// <summary>Adds a new profile and returns it (with any repository-assigned defaults applied).</summary>
    ProxyProfile Add(ProxyProfile profile);

    /// <summary>Updates an existing profile in place. Throws if the id is not found.</summary>
    void Update(ProxyProfile profile);

    /// <summary>Deletes a profile (and its associated stored credential) by id.</summary>
    void Delete(Guid id);

    /// <summary>Persists the currently selected proxy id (nullable to allow "none selected").</summary>
    void SetSelected(Guid? id);

    Guid? GetSelectedId();
}
