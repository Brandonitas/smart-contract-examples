// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

contract SupplyChain {
    struct Step {
        Status status;
        string metadata;
    }

    enum Status {
        CREATED,
        READY_FOR_PICK_UP,
        PICKED_UP,
        READY_FOR_DELIVERY,
        DELIVERED
    }

    // Evento para lanzar con cada nuevo Step de la cadena
    event RegisteredStep(
        uint256 productId,
        Status status,
        string metadata,
        address author
    );

    // El mapping guarda el ID de la cadena y un array asociado con cada Step de la misma
    mapping(uint256 => Step[]) public products;

    // Registrar nuevo producto que contendrá Steps
    function registerProduct(uint256 productId) public returns (bool success) {
        require(products[productId].length == 0, "This product already exists");
        products[productId].push(Step(Status.CREATED, ""));
        return success;
    }

    // Registrar un nuevo Step en un producto
    function registerStep(
        uint256 productId,
        string calldata metadata
    ) public returns (bool success) {
        // Verificamos la existencia del producto
        require(products[productId].length > 0, "This product doesn't exist");
        Step[] memory stepsArray = products[productId];

        // Incrementamos en uno el estado de los Steps del producto
        uint256 currentStatus = uint256(
            stepsArray[stepsArray.length - 1].status
        ) + 1;

        // Verificamos que no se exceda la cantidad de pasos disponible
        if (currentStatus > uint256(Status.DELIVERED)) {
            revert("The product has no more steps");
        }

        // Construimos la información del Step
        Step memory step = Step(Status(currentStatus), metadata);

        // Guardamos el Step en el array del producto
        products[productId].push(step);

        // Emitimos el evento y devolvemos un OK
        emit RegisteredStep(
            productId,
            Status(currentStatus),
            metadata,
            msg.sender
        );
        success = true;
    }
}
