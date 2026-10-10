// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title Trato Hecho — Custodia y aval de operaciones entre personas
/// @notice El contrato custodia una garantia en cripto mientras dos personas
///         concretan una operacion (cripto-fiat, cripto-cripto o fiat-fiat)
///         fuera de la cadena. No participa del intercambio en si: solo
///         retiene el aval y deja constancia (evidencia) de cada paso.
contract TratoHecho is Ownable {
    using SafeERC20 for IERC20;

    enum Estado {
        Creado,
        TransferenciaHabilitada,
        EnProceso,
        Entregado,
        Liberado,
        EnDisputa,
        Cancelado
    }

    enum TipoResolucion {
        TransferenciaYEnvio,   // Caso A
        EfectivoPorCorreo,     // Caso B
        Presencial             // Caso C
    }

    struct Trato {
        address vendedor;
        address comprador;
        address tokenGarantia;
        uint256 montoGarantia;
        uint256 plazoLimite;       // timestamp
        Estado estado;
        TipoResolucion tipo;
        string activoOfrecido;     // ej: "CLP efectivo", "USDC", metadata informativa
        string activoSolicitado;   // ej: "ARS transferencia"
        bytes32 hashDeclaracionJurada;
        bool envioVendedorConfirmado;
        bool envioCompradorConfirmado;
        string trackingVendedor;
        string trackingComprador;
        bytes32 hashPlanillaPresencial;
        bool existe;
    }

    /// @dev Wallets habilitadas para operar tras pasar KYC externo (Didit u otro proveedor).
    ///      Se marca desde un backend liviano que recibe el webhook de verificacion.
    mapping(address => bool) public kycVerificado;

    /// @dev Direcciones autorizadas a marcar KYC (el owner + backends delegados).
    mapping(address => bool) public verificadoresAutorizados;

    mapping(bytes32 => Trato) private tratos;

    event KycActualizado(address indexed persona, bool verificado);
    event TratoCreado(bytes32 indexed tratoId, address indexed vendedor, address indexed comprador, uint256 monto);
    event TransferenciaHabilitada(bytes32 indexed tratoId);
    event DeclaracionJuradaRegistrada(bytes32 indexed tratoId, bytes32 hashDeclaracion);
    event EnvioRegistrado(bytes32 indexed tratoId, address indexed quien, string tracking);
    event RecepcionConfirmada(bytes32 indexed tratoId, address indexed quien);
    event FirmaPresencialRegistrada(bytes32 indexed tratoId, bytes32 hashPlanilla);
    event GarantiaLiberada(bytes32 indexed tratoId, address indexed destinatario, uint256 monto);
    event DisputaAbierta(bytes32 indexed tratoId, address indexed quienAbre, string motivo);
    event DisputaResuelta(bytes32 indexed tratoId, address indexed ganador);
    event TratoCancelado(bytes32 indexed tratoId);

    modifier soloParticipante(bytes32 _tratoId) {
        Trato storage t = tratos[_tratoId];
        require(msg.sender == t.vendedor || msg.sender == t.comprador, "No sos parte de este trato");
        _;
    }

    modifier tratoExiste(bytes32 _tratoId) {
        require(tratos[_tratoId].existe, "El trato no existe");
        _;
    }

    constructor() Ownable(msg.sender) {
        verificadoresAutorizados[msg.sender] = true;
    }

    // ============ KYC ============

    function autorizarVerificador(address _verificador, bool _autorizado) external onlyOwner {
        verificadoresAutorizados[_verificador] = _autorizado;
    }

    /// @notice Marca una wallet como verificada por KYC. Llamado por el backend
    ///         liviano que procesa el webhook de aprobacion de Didit (u otro proveedor).
    function marcarKyc(address _persona, bool _verificado) external {
        require(verificadoresAutorizados[msg.sender], "No autorizado a marcar KYC");
        kycVerificado[_persona] = _verificado;
        emit KycActualizado(_persona, _verificado);
    }

    // ============ CREACION DEL TRATO ============

    struct ParametrosTrato {
        bytes32 tratoId;
        address comprador;
        address tokenGarantia;
        uint256 montoGarantia;
        uint256 diasPlazo;
        TipoResolucion tipo;
        string activoOfrecido;
        string activoSolicitado;
    }

    function crearYGarantizarTrato(ParametrosTrato calldata _p) external {
        require(!tratos[_p.tratoId].existe, "Ese ID de trato ya existe");
        require(kycVerificado[msg.sender], "Vendedor sin KYC verificado");
        require(kycVerificado[_p.comprador], "Comprador sin KYC verificado");
        require(_p.comprador != address(0) && _p.comprador != msg.sender, "Comprador invalido");
        require(_p.montoGarantia > 0, "El monto de garantia debe ser mayor a cero");

        Trato storage t = tratos[_p.tratoId];
        t.vendedor = msg.sender;
        t.comprador = _p.comprador;
        t.tokenGarantia = _p.tokenGarantia;
        t.montoGarantia = _p.montoGarantia;
        t.plazoLimite = block.timestamp + (_p.diasPlazo * 1 days);
        t.estado = Estado.Creado;
        t.tipo = _p.tipo;
        t.activoOfrecido = _p.activoOfrecido;
        t.activoSolicitado = _p.activoSolicitado;
        t.existe = true;

        IERC20(_p.tokenGarantia).safeTransferFrom(msg.sender, address(this), _p.montoGarantia);

        emit TratoCreado(_p.tratoId, msg.sender, _p.comprador, _p.montoGarantia);
    }

    /// @notice Ambas partes firman (hash de) la declaracion jurada donde aceptan
    ///         los terminos y el alcance del servicio de Trato Hecho.
    function registrarDeclaracionJurada(bytes32 _tratoId, bytes32 _hashDeclaracion)
        external
        tratoExiste(_tratoId)
        soloParticipante(_tratoId)
    {
        tratos[_tratoId].hashDeclaracionJurada = _hashDeclaracion;
        emit DeclaracionJuradaRegistrada(_tratoId, _hashDeclaracion);
    }

    // ============ CASO A: transferencia + envio postal ============

    function habilitarTransferencia(bytes32 _tratoId) external tratoExiste(_tratoId) {
        Trato storage t = tratos[_tratoId];
        require(msg.sender == t.vendedor, "Solo el vendedor habilita la transferencia");
        require(t.estado == Estado.Creado, "Estado invalido");
        t.estado = Estado.TransferenciaHabilitada;
        emit TransferenciaHabilitada(_tratoId);
    }

    // ============ CASOS A y B: registro de envios ============

    /// @dev En el caso A solo despacha el vendedor; en el caso B despachan ambos.
    function registrarEnvio(bytes32 _tratoId, string calldata _trackingCode)
        external
        tratoExiste(_tratoId)
        soloParticipante(_tratoId)
    {
        Trato storage t = tratos[_tratoId];
        t.estado = Estado.EnProceso;
        if (msg.sender == t.vendedor) {
            t.trackingVendedor = _trackingCode;
            t.envioVendedorConfirmado = true;
        } else {
            t.trackingComprador = _trackingCode;
            t.envioCompradorConfirmado = true;
        }
        emit EnvioRegistrado(_tratoId, msg.sender, _trackingCode);
    }

    function confirmarRecepcion(bytes32 _tratoId)
        external
        tratoExiste(_tratoId)
        soloParticipante(_tratoId)
    {
        Trato storage t = tratos[_tratoId];

        if (t.tipo == TipoResolucion.TransferenciaYEnvio) {
            require(msg.sender == t.comprador, "Solo el comprador confirma recepcion en Caso A");
            require(t.envioVendedorConfirmado, "El vendedor aun no despacho el envio");
            t.estado = Estado.Entregado;
            emit RecepcionConfirmada(_tratoId, msg.sender);
            _liberar(_tratoId, t.vendedor);
        } else if (t.tipo == TipoResolucion.EfectivoPorCorreo) {
            require(t.envioVendedorConfirmado && t.envioCompradorConfirmado, "Faltan despachos de ambas partes");
            t.estado = Estado.Entregado;
            emit RecepcionConfirmada(_tratoId, msg.sender);
            _liberar(_tratoId, t.vendedor);
        } else {
            revert("Este trato usa el flujo presencial");
        }
    }

    // ============ CASO C: encuentro presencial ============

    function registrarFirmaPresencial(bytes32 _tratoId, bytes32 _hashPlanilla)
        external
        tratoExiste(_tratoId)
        soloParticipante(_tratoId)
    {
        Trato storage t = tratos[_tratoId];
        require(t.tipo == TipoResolucion.Presencial, "Este trato no es presencial");
        t.hashPlanillaPresencial = _hashPlanilla;
        t.estado = Estado.Entregado;
        emit FirmaPresencialRegistrada(_tratoId, _hashPlanilla);
        _liberar(_tratoId, t.vendedor);
    }

    // ============ LIBERACION Y DISPUTAS ============

    function _liberar(bytes32 _tratoId, address _destinatario) internal {
        Trato storage t = tratos[_tratoId];
        require(t.estado != Estado.Liberado, "Ya fue liberado");
        uint256 monto = t.montoGarantia;
        t.estado = Estado.Liberado;
        t.montoGarantia = 0;
        IERC20(t.tokenGarantia).safeTransfer(_destinatario, monto);
        emit GarantiaLiberada(_tratoId, _destinatario, monto);
    }

    function abrirDisputa(bytes32 _tratoId, string calldata _motivo)
        external
        tratoExiste(_tratoId)
        soloParticipante(_tratoId)
    {
        Trato storage t = tratos[_tratoId];
        require(t.estado != Estado.Liberado, "El trato ya fue liberado");
        t.estado = Estado.EnDisputa;
        emit DisputaAbierta(_tratoId, msg.sender, _motivo);
    }

    /// @notice Resolucion administrativa de una disputa, dentro del alcance del
    ///         servicio de aval. No reemplaza una instancia judicial.
    function resolverDisputa(bytes32 _tratoId, address _ganador) external onlyOwner tratoExiste(_tratoId) {
        Trato storage t = tratos[_tratoId];
        require(t.estado == Estado.EnDisputa, "El trato no esta en disputa");
        require(_ganador == t.vendedor || _ganador == t.comprador, "Ganador invalido");
        emit DisputaResuelta(_tratoId, _ganador);
        _liberar(_tratoId, _ganador);
    }

    function cancelarTrato(bytes32 _tratoId) external tratoExiste(_tratoId) {
        Trato storage t = tratos[_tratoId];
        require(msg.sender == t.vendedor, "Solo el vendedor puede cancelar");
        require(t.estado == Estado.Creado, "Ya esta en curso, no se puede cancelar");
        t.estado = Estado.Cancelado;
        uint256 monto = t.montoGarantia;
        t.montoGarantia = 0;
        IERC20(t.tokenGarantia).safeTransfer(t.vendedor, monto);
        emit TratoCancelado(_tratoId);
    }

    // ============ LECTURA ============
    // Partido en varias funciones chicas (en vez de una que devuelva
    // el struct completo) para no repetir el problema de "stack too deep".

    function obtenerTratoBasico(bytes32 _tratoId) external view returns (
        address vendedor,
        address comprador,
        address tokenGarantia,
        uint256 montoGarantia,
        uint256 plazoLimite,
        Estado estado,
        TipoResolucion tipo
    ) {
        Trato storage t = tratos[_tratoId];
        return (t.vendedor, t.comprador, t.tokenGarantia, t.montoGarantia, t.plazoLimite, t.estado, t.tipo);
    }

    function obtenerTratoActivos(bytes32 _tratoId) external view returns (
        string memory activoOfrecido,
        string memory activoSolicitado
    ) {
        Trato storage t = tratos[_tratoId];
        return (t.activoOfrecido, t.activoSolicitado);
    }

    function obtenerTratoEnvios(bytes32 _tratoId) external view returns (
        bool envioVendedorConfirmado,
        bool envioCompradorConfirmado,
        string memory trackingVendedor,
        string memory trackingComprador
    ) {
        Trato storage t = tratos[_tratoId];
        return (t.envioVendedorConfirmado, t.envioCompradorConfirmado, t.trackingVendedor, t.trackingComprador);
    }

    function obtenerTratoEvidencia(bytes32 _tratoId) external view returns (
        bytes32 hashDeclaracionJurada,
        bytes32 hashPlanillaPresencial,
        bool existe
    ) {
        Trato storage t = tratos[_tratoId];
        return (t.hashDeclaracionJurada, t.hashPlanillaPresencial, t.existe);
    }
}
